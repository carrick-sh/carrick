//! Native leaf hooks for the bounded CPL0 lifecycle execution witness.
//! Claims, runnable/wait queues, birth publication and Linux policy are shared
//! owners. This two-context sidecar is fixture hardware custody, not a binding
//! of the runtime's production executor pool.
use crate::cpl0_entry::{CpuBinding, NativeFrame};
use crate::cpl0_scheduler::XsaveArea;
#[cfg(target_os = "none")]
use crate::cpl0_scheduler::{
    NativeTlsRegister, read_tls, restore_extended, save_extended, write_tls,
};
use carrick_core_abi::EntryMmKey;
use carrick_el1_abi::{Counters, CurrentTask, EntryRef, ThreadControlSlot, ThreadLifecyclePage};
use carrick_guest_arch::{RootGpa, UserVa};
use carrick_personality_linux::abi::entry::SyscallResult;
#[cfg(target_os = "none")]
use carrick_personality_linux::lifecycle::LifecycleOutcome;
use carrick_personality_linux::{
    abi::thread::LifecycleDecline,
    dispatch::{EntryCounters, FamilyCompletion, PendingFamilies},
    lifecycle::{ChildContext, ExitRecord, LifecycleNative, UserCopy},
    sched::{FutexCall, FutexFrequency, FutexVenue, FutexWait},
    thread::LifecycleThread,
};
use carrick_sched_core::{
    BoundedSpin, Claim, RecordRef, SlotId, ThreadIdentity, WakeEffects, Waker, ZoneTables,
};
use core::sync::atomic::{AtomicU16, Ordering};

/// Terminal native-custody failures after guest mutation. These are kernel
/// invariant errors, never a request to replay the syscall on the host.
#[repr(u64)]
#[derive(Clone, Copy, Debug)]
pub enum LifecycleInvariant {
    ForkBacking = 0x101,
    ForkCommit,
    ForkPublication,
    WaitEnrollment,
    WaitPublication,
    WaitSwitch,
    ExitPublication,
    ExitWake,
    ExitReap,
    ExitRecord,
    ExitRetirement,
    ExitSwitch,
}
#[cfg(target_os = "none")]
fn committed<T>(value: Option<T>, reason: LifecycleInvariant) -> T {
    value.unwrap_or_else(|| crate::kernel::lifecycle_invariant_error(reason))
}

const CHILD_WAIT_KEY: u64 = 0x5_0300;

/// A fresh host-loaded home record remains private until park publication.
/// Refusal returns that allocation; a switched-in record remains its owner's.
#[cfg(target_os = "none")]
struct PendingWaitRecord<'a> {
    zone: &'a ZoneTables,
    slot: SlotId,
    record: carrick_sched_core::RecordId,
    unpublished: bool,
}
#[cfg(target_os = "none")]
impl<'a> PendingWaitRecord<'a> {
    fn acquire(zone: &'a ZoneTables, slot: SlotId, identity: ThreadIdentity) -> Option<Self> {
        let unpublished = zone.slot(slot).current().is_none();
        let record = zone.current_or_new(slot, identity).ok()?;
        Some(Self {
            zone,
            slot,
            record,
            unpublished,
        })
    }

    fn published(mut self) {
        self.unpublished = false;
    }
}
#[cfg(target_os = "none")]
impl Drop for PendingWaitRecord<'_> {
    fn drop(&mut self) {
        if self.unpublished {
            self.zone.discard_unpublished(self.slot, self.record);
        }
    }
}

/// Owned exclusion for child exit publication and wait enrollment. The
/// constructor is the only way to acquire this exact MM's child-wait bucket.
pub struct ChildWaitGuard<'a> {
    bucket: carrick_sched_core::BucketGuard<'a>,
    parent_mm: EntryMmKey,
    exit: &'a ChildExitRecord,
}
impl<'a> ChildWaitGuard<'a> {
    fn acquire(zone: &'a ZoneTables, exit: &'a ChildExitRecord) -> Option<Self> {
        let parent_mm = exit.parent_mm;
        Some(Self {
            bucket: zone.lock(
                ZoneTables::bucket_of(parent_mm.raw(), CHILD_WAIT_KEY),
                &BoundedSpin(1024),
            )?,
            parent_mm,
            exit,
        })
    }

    #[cfg(target_os = "none")]
    fn enroll(
        &self,
        record: carrick_sched_core::RecordId,
        seq: u32,
        child_pid: u32,
    ) -> Result<(), carrick_sched_core::Exhausted> {
        self.bucket.zone().enqueue(
            &self.bucket,
            record,
            seq,
            self.parent_mm.raw(),
            CHILD_WAIT_KEY,
            u32::MAX,
            child_pid,
        )
    }
}

/// Retained one-child fixture exit record. Zero is live, 1..=256 is a zombie
/// carrying the Linux eight-bit exit code, and 257 is reaped. The wait-bucket
/// lock couples publication with park/wake; atomics preserve stopped-host
/// observation and make accidental second reaping fail closed.
///
/// Exit publication requires the same owned bucket guard as wait enrollment.
/// ```compile_fail
/// use carrick_x86::cpl0_lifecycle::ChildExitRecord;
/// let record = ChildExitRecord::new(carrick_core_abi::EntryMmKey::from_raw(77));
/// record.publish_exit(3);
/// ```
pub struct ChildExitRecord {
    state: AtomicU16,
    parent_mm: EntryMmKey,
}
/// Unique proof that the child was consumed, required for guest output writes.
pub struct ReapedChild {
    status: u8,
    parent_mm: EntryMmKey,
}
impl ReapedChild {
    pub fn status(&self) -> u8 {
        self.status
    }
    pub fn parent_mm(&self) -> EntryMmKey {
        self.parent_mm
    }
}
impl ChildExitRecord {
    pub const fn new(parent_mm: EntryMmKey) -> Self {
        Self {
            state: AtomicU16::new(0),
            parent_mm,
        }
    }
    pub fn lock<'a>(&'a self, zone: &'a ZoneTables) -> Option<ChildWaitGuard<'a>> {
        ChildWaitGuard::acquire(zone, self)
    }
    pub fn publish_exit(&self, guard: &ChildWaitGuard<'_>, status: u8) -> bool {
        if !core::ptr::eq(guard.exit, self)
            || guard.parent_mm != self.parent_mm
            || guard.bucket.bucket() != ZoneTables::bucket_of(self.parent_mm.raw(), CHILD_WAIT_KEY)
        {
            return false;
        }
        self.state
            .compare_exchange(
                0,
                u16::from(status) + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }
    pub fn exited_status(&self) -> Option<u8> {
        let state = self.state.load(Ordering::Acquire);
        (1..=256).contains(&state).then(|| (state - 1) as u8)
    }
    pub fn reap(&self, guard: &ChildWaitGuard<'_>, status: u8) -> Option<ReapedChild> {
        if !core::ptr::eq(guard.exit, self) {
            return None;
        }
        self.state
            .compare_exchange(
                u16::from(status) + 1,
                257,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .ok()
            .map(|_| ReapedChild {
                status,
                parent_mm: self.parent_mm,
            })
    }
    pub fn reaped(&self) -> bool {
        self.state.load(Ordering::Acquire) == 257
    }
}

#[cfg(test)]
mod process_exit_tests {
    use super::ChildExitRecord;
    use carrick_sched_core::ZoneTables;

    #[test]
    fn child_exit_preserves_an_unrelated_runnable_context_result() {
        use super::*;
        let zone = unsafe {
            // SAFETY: aligned zeroed allocation is the empty ZoneTables representation.
            let pointer = std::alloc::alloc_zeroed(std::alloc::Layout::new::<ZoneTables>())
                .cast::<ZoneTables>();
            assert!(!pointer.is_null());
            std::boxed::Box::from_raw(pointer)
        };
        let slot = SlotId::new(0);
        let parent = ThreadIdentity {
            tid: 41,
            serial: 101,
            mm: 77,
            file_table: 5,
            generation: 11,
            affinity: 1,
            lifecycle_page: 0,
            control_slot: 0,
        };
        zone.drive(slot, 1);
        zone.publish_slot(slot, parent.mm, Some(0), 0);
        let space = zone
            .spaces
            .publish_closed(parent.mm, 0x1000, 0)
            .expect("space");
        zone.spaces.open(space);
        let id = zone.alloc_record(parent).expect("runnable parent");
        zone.requeue_preempted(slot, id);
        let mut lane = LifecycleLane {
            contexts: [const { NativeBirthContext::EMPTY }; 2],
            parent,
            slot,
            maintenance_root: RootGpa::page_aligned(carrick_guest_arch::FrameGpa::new(0x1000))
                .expect("maintenance root"),
            data_start: 0,
            data_end: 0,
            wakes: 0,
            births: 0,
            retirements: 0,
        };
        lane.contexts[0].record = Some(zone.record_ref(id));
        lane.contexts[0].frame.rax = 0xabcdef;
        let task = CurrentTask::new();
        let counters = Counters::new();
        let page = ThreadLifecyclePage::new();
        let controls = core::array::from_fn(|_| ThreadControlSlot::new());
        let mut frame = NativeFrame::default();
        let mut native = NativeLane {
            handoff: None,
            frame: &mut frame,
            task: &task,
            counters: &counters,
            zone: &zone,
            lane: &mut lane,
            page: &page,
            controls: &controls,
            args: [0; 6],
        };
        assert!(native.resume_after_child_exit().is_some());
        assert_eq!(native.frame.rax, 0xabcdef);
        assert_eq!(task.mm.key.load(Ordering::Acquire), parent.mm);
    }

    #[test]
    fn child_exits_before_parent_waits_and_is_reaped_once() {
        let record = ChildExitRecord::new(carrick_core_abi::EntryMmKey::from_raw(77));
        // SAFETY: typed zeroed allocation preserves the ZoneTables alignment;
        // its FromZeros representation permits an empty retained fixture.
        let zone = unsafe {
            let pointer = std::alloc::alloc_zeroed(std::alloc::Layout::new::<ZoneTables>())
                .cast::<ZoneTables>();
            assert!(!pointer.is_null());
            std::boxed::Box::from_raw(pointer)
        };
        let guard = record.lock(&zone).expect("child wait guard");
        assert!(record.lock(&zone).is_none());
        let other = ChildExitRecord::new(carrick_core_abi::EntryMmKey::from_raw(77));
        assert!(!other.publish_exit(&guard, 3));
        assert!(other.reap(&guard, 3).is_none());
        assert!(record.publish_exit(&guard, 3));
        assert_eq!(record.exited_status(), Some(3));
        assert!(record.reap(&guard, 3).is_some());
        assert_eq!(record.exited_status(), None);
        assert!(record.reap(&guard, 3).is_none());
    }
}

pub const LIFECYCLE_ZONE: u64 = 0xffff_ffff_b000_0000;
pub const LIFECYCLE_LANE: u64 = 0xffff_ffff_b090_0000;
pub const LIFECYCLE_STRIDE: u64 = 0x1_0000;
#[cfg(not(target_os = "none"))]
pub const LIFECYCLE_DATA: u64 = 0x5_0000;

#[repr(C)]
#[derive(Clone)]
pub struct NativeBirthContext {
    pub record: Option<RecordRef>,
    pub frame: NativeFrame,
    pub fs_base: u64,
    pub gs_base: u64,
    pub xsave: XsaveArea,
}
impl NativeBirthContext {
    #[cfg(not(target_os = "none"))]
    pub const EMPTY: Self = Self {
        record: None,
        frame: NativeFrame {
            r15: 0,
            r14: 0,
            r13: 0,
            r12: 0,
            rbp: 0,
            rbx: 0,
            r9: 0,
            r8: 0,
            r10: 0,
            rdx: 0,
            rsi: 0,
            rdi: 0,
            rax: 0,
            rcx: 0,
            r11: 0,
            rsp: 0,
        },
        fs_base: 0,
        gs_base: 0,
        xsave: XsaveArea::ZERO,
    };
}
#[repr(C)]
pub struct LifecycleLane {
    pub contexts: [NativeBirthContext; 2],
    pub parent: ThreadIdentity,
    pub slot: SlotId,
    pub maintenance_root: RootGpa,
    pub data_start: u64,
    pub data_end: u64,
    pub wakes: u64,
    pub births: u64,
    pub retirements: u64,
}

pub struct NativeLane<'a> {
    handoff: Option<carrick_core_abi::EntryHandoffReceipt>,
    pub frame: &'a mut NativeFrame,
    pub task: &'a CurrentTask,
    pub counters: &'a Counters,
    pub zone: &'a ZoneTables,
    pub lane: &'a mut LifecycleLane,
    pub page: &'a ThreadLifecyclePage,
    pub controls: &'a [ThreadControlSlot; 9],
    pub args: [u64; 6],
}
impl NativeLane<'_> {
    #[cfg(any(target_os = "none", test))]
    fn resume_after_child_exit(
        &mut self,
    ) -> Option<carrick_personality_linux::lifecycle::LifecycleOutcome> {
        let progress = self.switch_next()?;
        Some(
            carrick_personality_linux::lifecycle::LifecycleOutcome::Transferred {
                progress,
                result: SyscallResult::new(self.frame.rax as i64),
            },
        )
    }
    fn current_index(&self) -> usize {
        usize::from(self.task.execution.task.load(Ordering::Acquire) != self.lane.parent.tid)
    }
    fn valid_user_range(&self, start: u64, size: usize) -> bool {
        start >= self.lane.data_start
            && start
                .checked_add(size as u64)
                .is_some_and(|end| end <= self.lane.data_end)
    }
    fn wake_word(&mut self, mm: u64, address: u64, mask: u32, limit: u32) -> bool {
        let Some(guard) = self
            .zone
            .lock(ZoneTables::bucket_of(mm, address), &BoundedSpin(1024))
        else {
            return false;
        };
        let mut effects = WakeEffects::default();
        let result = self.zone.wake_placed(
            &guard,
            mm,
            address,
            mask,
            limit,
            Waker::El1 {
                slot: self.lane.slot,
            },
            &mut [],
            &mut effects,
        );
        if let Ok(count) = result {
            self.frame.rax = u64::from(count);
            self.lane.wakes += u64::from(count);
            true
        } else {
            false
        }
    }
    fn switch_next(&mut self) -> Option<carrick_core::Served> {
        let switched = self.zone.switch_in_full(self.lane.slot)?;
        let reference = self.zone.record_ref(switched.record);
        let index = self
            .lane
            .contexts
            .iter()
            .position(|ctx| ctx.record == Some(reference))?;
        let identity = self.zone.record(switched.record).identity();
        let context = self.lane.contexts[index].clone();
        #[cfg(target_os = "none")]
        let changed_mm = self.zone.installed_space(self.lane.slot) != identity.mm;
        #[cfg(target_os = "none")]
        if changed_mm {
            use carrick_guest_arch::{AddressContext, ContextGeneration, MmGeneration, MmuBackend};
            let context = AddressContext {
                root: self.lane.maintenance_root,
                mm: MmGeneration::new(core::num::NonZeroU64::MIN),
                generation: ContextGeneration::new(core::num::NonZeroU64::MIN),
            };
            carrick_el1::isa::x86::X86Backend
                .install_context(context)
                .ok()?;
        }
        self.zone.release_space(self.lane.slot);
        let grant = self.zone.install_space(self.lane.slot, identity.mm)?;
        #[cfg(target_os = "none")]
        if changed_mm {
            use carrick_guest_arch::{
                AddressContext, ContextGeneration, FrameGpa, MmGeneration, MmuBackend, RootGpa,
            };
            let root = RootGpa::page_aligned(FrameGpa::new(grant.ttbr0))?;
            let mm = core::num::NonZeroU64::new(identity.mm)?;
            let generation = core::num::NonZeroU64::new(identity.generation)?;
            carrick_el1::isa::x86::X86Backend
                .install_context(AddressContext {
                    root,
                    mm: MmGeneration::new(mm),
                    generation: ContextGeneration::new(generation),
                })
                .ok()?;
        }
        #[cfg(not(target_os = "none"))]
        let _ = grant;
        *self.frame = context.frame;
        if let Some(result) = switched.result {
            self.frame.rax = result;
        }
        self.task
            .execution
            .task
            .store(identity.tid, Ordering::Relaxed);
        self.task
            .mm
            .thread_generation
            .store(identity.serial, Ordering::Relaxed);
        self.task.mm.key.store(identity.mm, Ordering::Relaxed);
        self.task
            .publish_lifecycle(identity.lifecycle_page, identity.control_slot);
        self.task
            .execution
            .generation
            .store(identity.generation, Ordering::Release);
        #[cfg(target_os = "none")]
        {
            write_tls(NativeTlsRegister::Fs, context.fs_base);
            write_tls(NativeTlsRegister::UserGs, context.gs_base);
            restore_extended(&context.xsave);
        }
        Some(carrick_core::Served::Returned { switched: true })
    }
}
impl UserCopy for NativeLane<'_> {
    fn copy_in(&mut self, dst: &mut [u8], address: UserVa) -> bool {
        if !self.valid_user_range(address.raw(), dst.len()) {
            return false;
        }
        // SAFETY: stopped-host provisioned user aperture, selected by this
        // exact lane/MM; the current native root retains its private backing.
        unsafe {
            core::ptr::copy_nonoverlapping(address.raw() as *const u8, dst.as_mut_ptr(), dst.len());
        }
        true
    }
    fn copy_out(&mut self, address: UserVa, src: &[u8]) -> bool {
        if !self.valid_user_range(address.raw(), src.len()) {
            return false;
        }
        // SAFETY: same retained writable exact-MM aperture as copy_in; fixture
        // copy buffers are supervisor stack storage and cannot alias it.
        unsafe {
            core::ptr::copy_nonoverlapping(src.as_ptr(), address.raw() as *mut u8, src.len());
        }
        true
    }
}
impl<'a> LifecycleNative<'a> for NativeLane<'a> {
    fn arguments(&self) -> [u64; 6] {
        self.args
    }
    fn binding(&self) -> Option<carrick_core_abi::ExecutionBinding> {
        Some(carrick_core::entry::binding(
            &self.task.execution,
            &self.task.mm,
        ))
    }
    fn task_state(&self) -> Option<&'a carrick_personality_linux::abi::entry::LinuxTaskState> {
        Some(&self.task.linux)
    }
    fn thread(&self) -> Option<LifecycleThread<'a>> {
        Some(LifecycleThread {
            page: self.page,
            slot: &self.controls[self.current_index()],
        })
    }
    fn born_slot(
        &self,
        page: &ThreadLifecyclePage,
        entry: EntryRef,
    ) -> Option<&'a ThreadControlSlot> {
        core::ptr::eq(page, self.page)
            .then(|| self.controls.get(entry.index() + 1))
            .flatten()
    }
    fn record_decline(&self, reason: LifecycleDecline) {
        self.counters.record_lifecycle_decline(reason);
    }
    fn has_scheduler(&self) -> bool {
        true
    }
    fn user_sp(&mut self) -> Option<UserVa> {
        Some(UserVa::new(self.frame.rsp))
    }
    fn affinity(&self) -> Option<u64> {
        Some(1u64 << self.lane.slot.raw())
    }
    fn allocate_record(
        &mut self,
        identity: ThreadIdentity,
    ) -> Result<RecordRef, carrick_sched_core::Exhausted> {
        self.zone
            .alloc_record(identity)
            .map(|id| self.zone.record_ref(id))
    }
    fn free_record(&mut self, record: RecordRef) {
        if self.zone.record(record.id).incarnation() == record.incarnation {
            self.zone.free_record(record.id);
        }
    }
    fn can_prepare_child(&self, stack: UserVa, tls: Option<UserVa>) -> bool {
        child_context_supported(stack, tls)
    }
    fn prepare_child(&mut self, record: RecordRef, context: ChildContext) {
        let mut frame = *self.frame;
        frame.rax = context.result.raw() as u64;
        frame.rsp = context.stack.raw();
        #[cfg(target_os = "none")]
        let inherited_tls = read_tls(NativeTlsRegister::Fs);
        #[cfg(not(target_os = "none"))]
        let inherited_tls = self.lane.contexts[self.current_index()].fs_base;
        #[cfg(target_os = "none")]
        let gs_base = read_tls(NativeTlsRegister::UserGs);
        #[cfg(not(target_os = "none"))]
        let gs_base = self.lane.contexts[self.current_index()].gs_base;
        let mut xsave = XsaveArea::ZERO;
        #[cfg(target_os = "none")]
        save_extended(&mut xsave);
        #[cfg(not(target_os = "none"))]
        xsave
            .0
            .copy_from_slice(&self.lane.contexts[self.current_index()].xsave.0);
        self.lane.contexts[1] = NativeBirthContext {
            record: Some(record),
            frame,
            fs_base: context.tls.map_or(inherited_tls, UserVa::raw),
            gs_base,
            xsave,
        };
    }
    fn enqueue_born(&mut self, record: RecordRef) {
        self.zone.requeue_preempted(self.lane.slot, record.id);
        self.lane.births += 1;
    }
    fn exit_record(&self) -> Option<ExitRecord> {
        let id = self.zone.slot(self.lane.slot).current()?;
        let rec = self.zone.record(id);
        Some(ExitRecord {
            reference: self.zone.record_ref(id),
            identity: rec.identity(),
            home: self.zone.slot(self.lane.slot).host_record() == Some(id),
            unadopted: rec.is_unadopted_birth(),
            on_cpu: matches!(rec.claim(), Claim::OnCpu { slot, .. } if slot == self.lane.slot),
            needs_host: rec.needs_host(),
            cancelled: rec.is_cancelled(),
            object_operation: rec.has_object_operation(),
        })
    }
    fn wake_child_tid(&mut self, mm: EntryMmKey, address: UserVa) -> bool {
        self.wake_word(
            mm.raw(),
            address.raw(),
            carrick_personality_linux::thread::CHILD_TID_WAKE_MASK,
            carrick_personality_linux::thread::CHILD_TID_WAKE_COUNT,
        )
    }
    fn release_current(&mut self, record: RecordRef) -> bool {
        if self.zone.live(record).is_none() {
            return false;
        }
        self.handoff = carrick_core::entry::retire_current(
            carrick_core::entry::binding(&self.task.execution, &self.task.mm),
            carrick_core_abi::BornInZoneSource {
                zone: self.zone,
                slot: self.lane.slot,
            },
            record.id,
            1024,
        );
        if self.handoff.is_some() {
            self.lane.retirements += 1;
            true
        } else {
            false
        }
    }
    fn run_next(&mut self, _: SyscallResult) -> (carrick_core::Served, SyscallResult) {
        let served = self.switch_next().unwrap_or(carrick_core::Served::Idle);
        (served, SyscallResult::new(self.frame.rax as i64))
    }
    fn result(&self) -> SyscallResult {
        SyscallResult::new(self.frame.rax as i64)
    }
    fn set_result(&mut self, result: SyscallResult) {
        self.frame.rax = result.raw() as u64;
    }
    #[cfg(target_os = "none")]
    fn process_fork(&mut self) -> Option<LifecycleOutcome> {
        if !crate::process::process_mode()
            || self.lane.slot.raw() != 0
            || self.task.mm.key.load(Ordering::Acquire) != crate::process::parent_mm()
        {
            return None;
        }
        let refused = || {
            Some(LifecycleOutcome::Returned {
                result: SyscallResult::new(carrick_syscall_abi::LINUX_EAGAIN.guest_retval()),
                work: false,
            })
        };
        if self.lane.contexts[1].record.is_some() {
            return refused();
        }
        let mut child = self.lane.parent;
        child.tid = crate::process::child_pid(child.tid);
        let Some(serial) = child.serial.checked_add(1) else {
            return refused();
        };
        child.serial = serial;
        let Some(generation) = child.generation.checked_add(1) else {
            return refused();
        };
        child.generation = generation;
        child.mm = crate::process::child_mm();
        let Some(control) = child
            .control_slot
            .checked_add(core::mem::size_of::<ThreadControlSlot>() as u64)
        else {
            return refused();
        };
        child.control_slot = control;
        let Some(visible_tid) = u32::try_from(child.tid).ok() else {
            return refused();
        };
        let Some(parent_root) = carrick_el1::isa::x86::hardware_live_root().ok() else {
            return refused();
        };
        let Some(residency) = crate::process::residency() else {
            return refused();
        };
        let Some(record) = self.zone.alloc_record(child).ok() else {
            return refused();
        };
        let reference = self.zone.record_ref(record);
        // Reserve scheduler capacity before the fork owner changes any MM,
        // COW grant or residency publication. The entry stays closed.
        let Some(index) = self.zone.spaces.publish_closed(
            child.mm,
            crate::process::child_root().address().raw(),
            0,
        ) else {
            self.zone.free_record(record);
            return refused();
        };
        committed(
            crate::process::publish_child_stack(residency, parent_root).then_some(()),
            LifecycleInvariant::ForkBacking,
        );
        let (child_root, publication) = committed(
            crate::process::fork_mm(parent_root),
            LifecycleInvariant::ForkCommit,
        );
        committed(
            (publication.mm_key == self.lane.parent.mm
                && publication.root_gpa == parent_root.address().raw()
                && child_root == crate::process::child_root())
            .then_some(()),
            LifecycleInvariant::ForkPublication,
        );
        self.zone.spaces.open(index);
        self.prepare_child(
            reference,
            ChildContext {
                result: SyscallResult::new(0),
                stack: UserVa::new(self.frame.rsp),
                tls: None,
                visible_tid,
            },
        );
        self.enqueue_born(reference);
        Some(LifecycleOutcome::Returned {
            result: SyscallResult::new(child.tid as i64),
            work: false,
        })
    }
    #[cfg(target_os = "none")]
    fn process_wait4(
        &mut self,
        pid: carrick_personality_linux::lifecycle::ProcessWaitPid,
        status: UserVa,
        options: carrick_syscall_abi::LinuxWaitOptions,
        _rusage: UserVa,
    ) -> Option<LifecycleOutcome> {
        use carrick_syscall_abi::LinuxWaitOptions;
        if !crate::process::process_mode()
            || self.task.mm.key.load(Ordering::Acquire) != crate::process::parent_mm()
        {
            return None;
        }
        let returned = |value| {
            Some(LifecycleOutcome::Returned {
                result: SyscallResult::new(value),
                work: false,
            })
        };
        if _rusage.raw() != 0 {
            return returned(carrick_syscall_abi::LinuxErrno::new(38).guest_retval());
        }
        if options.bits() & !LinuxWaitOptions::WAIT4_SUPPORTED.bits() != 0 {
            return returned(carrick_syscall_abi::LINUX_EINVAL.guest_retval()); // EINVAL
        }
        let child_pid = crate::process::child_pid(self.lane.parent.tid);
        if !matches!(i64::from(pid.raw()), -1 | 0) && i64::from(pid.raw()) != child_pid as i64
            || options.contains(LinuxWaitOptions::WCLONE)
                && !options.contains(LinuxWaitOptions::WALL)
            || self.lane.contexts[1].record.is_none()
            || crate::process::child_exit().reaped()
        {
            return returned(carrick_syscall_abi::LINUX_ECHILD.guest_retval()); // ECHILD
        }
        let Some(guard) = crate::process::child_exit().lock(self.zone) else {
            return returned(carrick_syscall_abi::LINUX_EAGAIN.guest_retval());
        };
        if crate::process::child_exit().reaped() {
            return returned(carrick_syscall_abi::LINUX_ECHILD.guest_retval());
        }
        let code = crate::process::child_exit().exited_status();
        if code.is_none() && options.contains(LinuxWaitOptions::WNOHANG) {
            return returned(0);
        }
        let Some(outputs) =
            crate::process::prepare_wait_outputs(self, status, UserVa::new(self.args[3]))
        else {
            return returned(carrick_syscall_abi::LINUX_EFAULT.guest_retval());
        };
        if let Some(code) = code {
            let Some(child) = crate::process::child_exit().reap(&guard, code) else {
                return returned(carrick_syscall_abi::LINUX_ECHILD.guest_retval());
            };
            outputs.complete(child);
            return returned(child_pid as i64);
        }
        let Some(pending) = PendingWaitRecord::acquire(self.zone, self.lane.slot, self.lane.parent)
        else {
            return returned(carrick_syscall_abi::LINUX_EAGAIN.guest_retval());
        };
        let record = pending.record;
        let child_index = committed(
            u32::try_from(child_pid).ok(),
            LifecycleInvariant::WaitEnrollment,
        );
        let reference = self.zone.record_ref(record);
        let mut xsave = XsaveArea::ZERO;
        save_extended(&mut xsave);
        let mut saved_frame = *self.frame;
        saved_frame.rax = child_pid;
        let context = NativeBirthContext {
            record: Some(reference),
            frame: saved_frame,
            fs_base: read_tls(NativeTlsRegister::Fs),
            gs_base: read_tls(NativeTlsRegister::UserGs),
            xsave,
        };
        let Some(start) = carrick_core::entry::prepare_handoff(
            carrick_core::entry::binding(&self.task.execution, &self.task.mm),
            carrick_core_abi::BornInZoneSource {
                zone: self.zone,
                slot: self.lane.slot,
            },
            record,
        ) else {
            return returned(carrick_syscall_abi::LINUX_EAGAIN.guest_retval());
        };
        let seq = self.zone.next_seq(record);
        if guard.enroll(record, seq, child_index).is_err() {
            return returned(carrick_syscall_abi::LINUX_EAGAIN.guest_retval());
        }
        self.frame.rax = child_pid;
        self.lane.contexts[0] = context;
        crate::process::publish_wait_outputs(outputs);
        self.handoff = Some(committed(
            carrick_core::entry::publish_handoff_park(
                start,
                &guard.bucket,
                carrick_core_abi::EntryRecordGeneration(seq),
            ),
            LifecycleInvariant::WaitPublication,
        ));
        pending.published();
        self.zone.clear_current(self.lane.slot);
        drop(guard);
        let progress = committed(self.switch_next(), LifecycleInvariant::WaitSwitch);
        Some(LifecycleOutcome::Transferred {
            progress,
            result: SyscallResult::new(self.frame.rax as i64),
        })
    }
    #[cfg(target_os = "none")]
    fn process_exit_group(&mut self, status: u8) -> Option<LifecycleOutcome> {
        if !crate::process::process_mode()
            || self.task.mm.key.load(Ordering::Acquire) != crate::process::child_mm()
        {
            return None;
        }
        let guard = committed(
            crate::process::child_exit().lock(self.zone),
            LifecycleInvariant::ExitPublication,
        );
        committed(
            crate::process::child_exit()
                .publish_exit(&guard, status)
                .then_some(()),
            LifecycleInvariant::ExitPublication,
        );
        let mut effects = WakeEffects::default();
        let count = committed(
            self.zone
                .wake_placed(
                    &guard.bucket,
                    crate::process::parent_mm(),
                    CHILD_WAIT_KEY,
                    u32::MAX,
                    1,
                    Waker::El1 {
                        slot: self.lane.slot,
                    },
                    &mut [],
                    &mut effects,
                )
                .ok(),
            LifecycleInvariant::ExitWake,
        );
        if count != 0 {
            let child = committed(
                crate::process::child_exit().reap(&guard, status),
                LifecycleInvariant::ExitReap,
            );
            crate::process::complete_published_wait_outputs(child);
            self.lane.wakes += u64::from(count);
        }
        drop(guard);
        let record = committed(
            self.zone.slot(self.lane.slot).current(),
            LifecycleInvariant::ExitRecord,
        );
        committed(
            self.release_current(self.zone.record_ref(record))
                .then_some(()),
            LifecycleInvariant::ExitRetirement,
        );
        Some(committed(
            self.resume_after_child_exit(),
            LifecycleInvariant::ExitSwitch,
        ))
    }
}
impl FutexVenue for NativeLane<'_> {
    type Served = carrick_core::Served;
    fn mm(&self) -> Option<carrick_core_abi::ReservationMm> {
        carrick_core_abi::ReservationMm::new(self.task.mm.key.load(Ordering::Acquire))
    }
    fn timed_wait_allowed(&self) -> bool {
        false
    }
    fn read_u64(&self, address: carrick_guest_arch::UserVa) -> Option<u64> {
        if !self.valid_user_range(address.raw(), 8) {
            return None;
        }
        // SAFETY: checked retained readable aperture in the currently installed MM.
        Some(unsafe { core::ptr::read_unaligned(address.raw() as *const u64) })
    }
    fn frequency(&self) -> FutexFrequency {
        FutexFrequency::from_hz(1)
    }
    fn now(&self) -> carrick_guest_arch::CounterTick {
        carrick_guest_arch::CounterTick::new(0)
    }
    fn wake(
        &mut self,
        mm: carrick_core_abi::ReservationMm,
        address: carrick_guest_arch::UserVa,
        mask: u32,
        limit: u32,
    ) -> Option<Self::Served> {
        self.wake_word(mm.raw(), address.raw(), mask, limit)
            .then_some(carrick_core::Served::Returned { switched: false })
    }
    fn wait(&mut self, wait: FutexWait) -> Option<Self::Served> {
        if !self.valid_user_range(wait.address.raw(), 4) {
            return None;
        }
        let guard = self.zone.lock(
            ZoneTables::bucket_of(wait.mm.raw(), wait.address.raw()),
            &BoundedSpin(1024),
        )?;
        // SAFETY: the exact installed MM's checked readable user aperture.
        let word = unsafe { core::ptr::read_unaligned(wait.address.raw() as *const u32) };
        if word != wait.expected {
            self.frame.rax = wait.mismatch_result.raw() as u64;
            return Some(carrick_core::Served::Returned { switched: false });
        }
        let record = self
            .zone
            .current_or_new(self.lane.slot, self.lane.parent)
            .ok()?;
        let reference = self.zone.record_ref(record);
        #[cfg(target_os = "none")]
        let fs_base = read_tls(NativeTlsRegister::Fs);
        #[cfg(not(target_os = "none"))]
        let fs_base = 0;
        #[cfg(target_os = "none")]
        let gs_base = read_tls(NativeTlsRegister::UserGs);
        #[cfg(not(target_os = "none"))]
        let gs_base = 0;
        let mut xsave = XsaveArea::ZERO;
        #[cfg(target_os = "none")]
        save_extended(&mut xsave);
        #[cfg(not(target_os = "none"))]
        xsave.0.copy_from_slice(&self.lane.contexts[0].xsave.0);
        self.lane.contexts[0] = NativeBirthContext {
            record: Some(reference),
            frame: *self.frame,
            fs_base,
            gs_base,
            xsave,
        };
        let start = carrick_core::entry::prepare_handoff(
            carrick_core::entry::binding(&self.task.execution, &self.task.mm),
            carrick_core_abi::BornInZoneSource {
                zone: self.zone,
                slot: self.lane.slot,
            },
            record,
        )?;
        let seq = self.zone.next_seq(record);
        self.zone
            .enqueue(
                &guard,
                record,
                seq,
                wait.mm.raw(),
                wait.address.raw(),
                wait.bitset,
                0,
            )
            .ok()?;
        self.handoff = Some(carrick_core::entry::publish_handoff_park(
            start,
            &guard,
            carrick_core_abi::EntryRecordGeneration(seq),
        )?);
        self.zone.clear_current(self.lane.slot);
        drop(guard);
        self.switch_next()
    }
}
impl<'a> PendingFamilies<'a> for NativeLane<'a> {
    fn take_handoff_receipt(&mut self) -> Option<carrick_core_abi::EntryHandoffReceipt> {
        self.handoff.take()
    }
    fn original_argument0(&self) -> u64 {
        self.args[0]
    }
    fn install_result(&mut self, result: SyscallResult) {
        self.frame.rax = result.raw() as u64;
    }
    fn binding(&self) -> Option<carrick_core_abi::ExecutionBinding> {
        LifecycleNative::binding(self)
    }
    fn record_source(&self) -> Option<carrick_core_abi::BornInZoneSource<'a>> {
        Some(carrick_core_abi::BornInZoneSource {
            zone: self.zone,
            slot: self.lane.slot,
        })
    }
    fn task_state(&self) -> Option<&carrick_personality_linux::abi::entry::LinuxTaskState> {
        Some(&self.task.linux)
    }
    fn lifecycle_native(&mut self) -> Option<&mut dyn LifecycleNative<'a>> {
        Some(self)
    }
    fn lifecycle_available(&self) -> bool {
        true
    }
    fn entry_counters(&self) -> Option<EntryCounters<'_>> {
        Some(EntryCounters {
            served: &self.counters.served,
            forwarded: &self.counters.forwarded,
        })
    }
    fn futex(&mut self) -> FamilyCompletion {
        let original = self.args[0];
        let Some(served) =
            carrick_personality_linux::sched::serve_futex(FutexCall { args: self.args }, self)
        else {
            return FamilyCompletion::Forward;
        };
        carrick_personality_linux::dispatch::transfer_effect(
            &self.task.linux,
            original,
            self.frame.rax as i64,
            served.into(),
        )
    }
}
/// Image acquisition of bounded retained native custody; no Linux routing here.
/// # Safety
/// The carrier must retain initialized aligned lane, zone and metadata storage
/// at these supervisor-only addresses until both fixture vCPUs stop.
pub unsafe fn acquire<'a>(
    frame: &'a mut NativeFrame,
    binding: &CpuBinding,
    task: &'a CurrentTask,
    counters: &'a Counters,
    args: [u64; 6],
) -> Option<NativeLane<'a>> {
    let address = binding.scheduler_witness.load(Ordering::Acquire);
    if address != LIFECYCLE_LANE && address != LIFECYCLE_LANE + LIFECYCLE_STRIDE {
        return None;
    }
    let index = (address - LIFECYCLE_LANE) / LIFECYCLE_STRIDE;
    // SAFETY: caller retains these exact supervisor mappings; fixed addresses
    // and stride distinguish the two live process sidecars and control arrays.
    let lane = unsafe { &mut *(address as *mut LifecycleLane) };
    // SAFETY: caller retains the initialized aligned supervisor zone mapping.
    let zone = unsafe { &*(LIFECYCLE_ZONE as *const ZoneTables) };
    // SAFETY: caller retains this exact lane's initialized aligned lifecycle page.
    let page = unsafe {
        &*((carrick_el1_abi::X86_CPL0_DYNAMIC_METADATA_BASE + index * 0x4000)
            as *const ThreadLifecyclePage)
    };
    // SAFETY: caller retains this exact lane's initialized aligned control array.
    let controls = unsafe {
        &*((carrick_el1_abi::X86_CPL0_DYNAMIC_METADATA_BASE + 0xb000 + index * 0x1000)
            as *const [ThreadControlSlot; 9])
    };
    Some(NativeLane {
        handoff: None,
        frame,
        task,
        counters,
        zone,
        lane,
        page,
        controls,
        args,
    })
}

/// Machine return/TLS qualification only; Linux retains clone flag and errno
/// policy. This bounded native binding uses the existing 48-bit user return
/// convention and refuses unavailable contexts before any shared birth effect.
pub fn child_context_supported(stack: UserVa, tls: Option<UserVa>) -> bool {
    stack.raw() != 0 && stack.raw() < (1u64 << 47) && tls.is_none_or(|tls| tls.raw() < (1u64 << 47))
}
