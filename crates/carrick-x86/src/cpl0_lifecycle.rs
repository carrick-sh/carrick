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
use carrick_guest_arch::UserVa;
use carrick_personality_linux::abi::entry::SyscallResult;
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
use core::sync::atomic::Ordering;

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
    pub data_start: u64,
    pub data_end: u64,
    pub wakes: u64,
    pub births: u64,
    pub retirements: u64,
}

pub struct NativeLane<'a> {
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
        self.zone.release_space(self.lane.slot);
        self.zone.install_space(self.lane.slot, identity.mm)?;
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
    fn release_current(&mut self, record: RecordRef) {
        if self.zone.live(record).is_some() {
            let _ = self
                .zone
                .release_current(self.lane.slot, record.id, &BoundedSpin(1024));
            self.lane.retirements += 1;
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
        if !self
            .zone
            .publish_guest_park(&guard, self.lane.slot, record, seq)
        {
            return None;
        }
        self.zone.clear_current(self.lane.slot);
        drop(guard);
        self.switch_next()
    }
}
impl<'a> PendingFamilies<'a> for NativeLane<'a> {
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
