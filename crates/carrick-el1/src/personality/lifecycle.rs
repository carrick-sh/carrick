//! ARM native context and mapping hooks for the shared Linux lifecycle owner.
use super::dispatch::{El1PendingFamilies, GuestDispatchFrame, native_scheduler};
use super::sched::{ThreadCpu, UserWord};
pub use super::thread_setup::{GuestLifecycleVenue, LifecycleVenue, guest_venue};
use crate::file::UserCopy as ArmUserCopy;
use carrick_el1_abi::EntryMmKey;
use carrick_el1_abi::{
    Claim, EntryRef, LifecycleDecline, RecordRef, ThreadControlSlot, ThreadCtx, ThreadIdentity,
    ThreadLifecyclePage,
};
use carrick_guest_arch::UserVa;
use carrick_personality_linux::abi::entry::LinuxTaskState;
use carrick_personality_linux::abi::entry::SyscallResult;
use carrick_personality_linux::entry::aarch64_child_vdso_identity;
pub use carrick_personality_linux::lifecycle::*;
pub use carrick_personality_linux::thread::{LifecycleThread, SYS_SET_ROBUST_LIST};

impl<
    'a,
    F: Fn(u32) -> *mut u8,
    C: ThreadCpu,
    U: UserWord,
    G: GuestDispatchFrame,
    Context: super::dispatch::DispatchContext,
> El1PendingFamilies<'a, F, C, U, G, Context>
{
    fn process_venue(&mut self) -> Option<&mut (dyn ProcessNative<Context> + 'a)> {
        let binding = LifecycleNative::binding(self)?;
        let venue = self.process.as_deref_mut()?;
        (venue.binding() == binding).then_some(venue)
    }
}

impl<
    F: Fn(u32) -> *mut u8,
    C: ThreadCpu,
    U: UserWord,
    G: GuestDispatchFrame,
    Context: super::dispatch::DispatchContext,
> UserCopy for El1PendingFamilies<'_, F, C, U, G, Context>
{
    fn copy_in(&mut self, dst: &mut [u8], src: UserVa) -> bool {
        #[cfg(test)]
        if let Some(user) = &mut self.lifecycle_user {
            return user.copy_in(dst, src.raw());
        }
        let Some(task) = self.current_tasks.get(self.frame.task_index()) else {
            return false;
        };
        crate::file::ValidatedCopy {
            task,
            validator: &crate::file::HardwareValidator,
        }
        .copy_in(dst, src.raw())
    }
    fn copy_out(&mut self, dst: UserVa, src: &[u8]) -> bool {
        #[cfg(test)]
        if let Some(user) = &mut self.lifecycle_user {
            return user.copy_out(dst.raw(), src);
        }
        let Some(task) = self.current_tasks.get(self.frame.task_index()) else {
            return false;
        };
        crate::file::ValidatedCopy {
            task,
            validator: &crate::file::HardwareValidator,
        }
        .copy_out(dst.raw(), src)
    }
}

impl<
    'a,
    F: Fn(u32) -> *mut u8,
    C: ThreadCpu,
    U: UserWord,
    G: GuestDispatchFrame,
    Context: super::dispatch::DispatchContext,
> LifecycleNative<'a> for El1PendingFamilies<'a, F, C, U, G, Context>
{
    fn process_fork(&mut self) -> Option<LifecycleOutcome> {
        Some(self.process_venue()?.fork())
    }
    fn process_wait4(
        &mut self,
        pid: ProcessWaitPid,
        status: UserVa,
        options: LinuxWaitOptions,
        rusage: UserVa,
    ) -> Option<LifecycleOutcome> {
        Some(self.process_venue()?.wait4(pid, status, options, rusage))
    }
    fn process_exit_group(&mut self, status: u8) -> Option<LifecycleOutcome> {
        Some(self.process_venue()?.exit_group(status))
    }
    fn arguments(&self) -> [u64; 6] {
        [
            self.frame.argument(0).unwrap_or(0),
            self.frame.argument(1).unwrap_or(0),
            self.frame.argument(2).unwrap_or(0),
            self.frame.argument(3).unwrap_or(0),
            self.frame.argument(4).unwrap_or(0),
            self.frame.argument(5).unwrap_or(0),
        ]
    }
    fn binding(&self) -> Option<carrick_el1_abi::ExecutionBinding> {
        self.current_tasks
            .get(self.frame.task_index())
            .map(super::common_entry::execution_binding)
    }
    fn process_pid(&self) -> Option<u32> {
        self.current_tasks
            .get(self.frame.task_index())?
            .visible_pid()
    }
    fn visible_tid(&self) -> Option<u32> {
        let binding = LifecycleNative::binding(self)?;
        let process = self.process.as_deref()?;
        if process.binding() != binding {
            return None;
        }
        self.thread()?.slot.visible_tid()
    }
    fn task_state(&self) -> Option<&'a LinuxTaskState> {
        self.current_tasks
            .get(self.frame.task_index())
            .map(|task| &task.linux)
    }
    fn thread(&self) -> Option<LifecycleThread<'a>> {
        self.lifecycle?
            .thread(self.current_tasks.get(self.frame.task_index())?)
    }
    fn register_robust_list(&self, head: u64, len: u64) -> Option<SyscallResult> {
        use super::thread_setup::{RobustListHead, RobustListLen, RobustListSlot};
        let task = self.current_tasks.get(self.frame.task_index())?;
        let thread = self.lifecycle?.thread(task)?;
        carrick_personality_linux::thread::set_robust_list(
            thread.page,
            RobustListSlot::new(thread.slot, self.frame.robust_publications()),
            RobustListHead::new(head),
            RobustListLen::new(len),
        )
        .linux_result()
        .map(SyscallResult::new)
    }
    fn born_slot(
        &self,
        page: &ThreadLifecyclePage,
        entry: EntryRef,
    ) -> Option<&'a ThreadControlSlot> {
        self.lifecycle?.born_slot(page, entry)
    }
    fn record_decline(&self, reason: LifecycleDecline) {
        self.counters.record_lifecycle_decline(reason);
    }
    fn has_scheduler(&self) -> bool {
        self.frame.arm_scheduler() && self.zone.is_some() && self.frame.slot().is_some()
    }
    fn can_prepare_child(&self, _: UserVa, _: Option<UserVa>) -> bool {
        if self.frame.arm_frame_ref().is_some() {
            true
        } else {
            self.frame.record_isa_unsupported_forward();
            false
        }
    }
    fn user_sp(&mut self) -> Option<UserVa> {
        if let Some(sp) = self.frame.user_sp() {
            return Some(sp);
        }
        let zone = self.zone.as_mut()?;
        let mut scratch = ThreadCtx::ZERO;
        zone.cpu.save(self.frame.arm_frame()?, &mut scratch);
        Some(UserVa::new(scratch.sp_el0))
    }
    fn affinity(&self) -> Option<u64> {
        let zone = self.zone.as_ref()?.tables;
        let slot = self.frame.slot()?;
        Some(match zone.slot(slot).current() {
            Some(record) => zone.record(record).identity().affinity,
            None => zone.slot(slot).affinity(),
        })
    }
    fn allocate_record(
        &mut self,
        identity: ThreadIdentity,
    ) -> Result<RecordRef, carrick_sched_core::Exhausted> {
        let zone = self
            .zone
            .as_ref()
            .ok_or(carrick_sched_core::Exhausted)?
            .tables;
        zone.alloc_record(identity)
            .map(|id| zone.record_ref(id))
            .map_err(|_| carrick_sched_core::Exhausted)
    }
    fn free_record(&mut self, record: RecordRef) {
        if let Some(zone) = &self.zone
            && zone.tables.record(record.id).incarnation() == record.incarnation
        {
            zone.tables.free_record(record.id);
        }
    }
    fn prepare_child(&mut self, record: RecordRef, context: ChildContext) {
        let Some(zone) = &mut self.zone else {
            return;
        };
        let rec = zone.tables.record(record.id);
        if rec.incarnation() != record.incarnation {
            return;
        }
        let record = rec;
        // SAFETY: this exact new record is unpublished and exclusively owned by this birth.
        let ctx = unsafe { record.ctx_mut() };
        let Some(frame) = self.frame.arm_frame() else {
            super::dispatch::invalid_completion(
                super::dispatch::NativeInvariant::MissingNativeFrame,
            );
        };
        zone.cpu.save(frame, ctx);
        ctx.x[0] = context.result.raw() as u64;
        ctx.sp_el0 = context.stack.raw();
        if let Some(tls) = context.tls {
            ctx.tpidr_el0 = tls.raw();
        }
        ctx.tpidrro_el0 = aarch64_child_vdso_identity(ctx.tpidrro_el0, context.visible_tid);
    }
    fn enqueue_born(&mut self, record: RecordRef) {
        let Some(task) = self.current_tasks.get(self.frame.task_index()) else {
            return;
        };
        let Some(slot) = self.frame.slot() else {
            return;
        };
        let Some(zone) = &mut self.zone else {
            return;
        };
        if zone.tables.record(record.id).incarnation() == record.incarnation {
            native_scheduler(zone, task, self.counters, slot, &mut self.handoff)
                .enqueue_born(record.id);
        }
    }
    fn exit_record(&self) -> Option<ExitRecord> {
        let zone = self.zone.as_ref()?.tables;
        let slot = self.frame.slot()?;
        let id = zone.slot(slot).current()?;
        let record = zone.record(id);
        Some(ExitRecord {
            reference: zone.record_ref(id),
            identity: record.identity(),
            home: zone.slot(slot).host_record() == Some(id),
            unadopted: record.is_unadopted_birth(),
            on_cpu: matches!(record.claim(), Claim::OnCpu {slot: owner, ..} if owner == slot),
            needs_host: record.needs_host(),
            cancelled: record.is_cancelled(),
            object_operation: record.has_object_operation(),
        })
    }
    fn wake_child_tid(&mut self, mm: EntryMmKey, address: UserVa) -> bool {
        let Some(task) = self.current_tasks.get(self.frame.task_index()) else {
            return false;
        };
        let Some(slot) = self.frame.slot() else {
            return false;
        };
        let Some(zone) = &mut self.zone else {
            return false;
        };
        native_scheduler(zone, task, self.counters, slot, &mut self.handoff)
            .wake_word(
                match self.frame.arm_frame() {
                    Some(frame) => frame,
                    None => return false,
                },
                mm.raw(),
                address.raw(),
                carrick_personality_linux::thread::CHILD_TID_WAKE_MASK,
                carrick_personality_linux::thread::CHILD_TID_WAKE_COUNT,
            )
            .is_some()
    }
    fn release_current(&mut self, record: RecordRef) -> bool {
        let Some(task) = self.current_tasks.get(self.frame.task_index()) else {
            return false;
        };
        let Some(zone) = &self.zone else {
            return false;
        };
        let Some(slot) = self.frame.slot() else {
            return false;
        };
        if zone.tables.live(record).is_none() {
            return false;
        }
        self.handoff = carrick_core::entry::retire_current(
            carrick_core::entry::binding(&task.execution, &task.mm),
            carrick_el1_abi::BornInZoneSource {
                zone: zone.tables,
                slot,
            },
            record.id,
            carrick_el1_abi::EL1_GUEST_LOCK_SPINS,
        );
        self.handoff.is_some()
    }
    fn run_next(&mut self, timeout_result: SyscallResult) -> (carrick_core::Served, SyscallResult) {
        let Some(task) = self.current_tasks.get(self.frame.task_index()) else {
            return (
                carrick_core::Served::Idle,
                SyscallResult::new(self.frame.result().0 as i64),
            );
        };
        let Some(slot) = self.frame.slot() else {
            return (
                carrick_core::Served::Idle,
                SyscallResult::new(self.frame.result().0 as i64),
            );
        };
        let Some(zone) = &mut self.zone else {
            return (
                carrick_core::Served::Idle,
                SyscallResult::new(self.frame.result().0 as i64),
            );
        };
        let served = native_scheduler(zone, task, self.counters, slot, &mut self.handoff).run_next(
            match self.frame.arm_frame() {
                Some(frame) => frame,
                None => super::dispatch::invalid_completion(
                    super::dispatch::NativeInvariant::MissingNativeFrame,
                ),
            },
            timeout_result.raw() as u64,
        );
        (served, SyscallResult::new(self.frame.result().0 as i64))
    }
    fn result(&self) -> SyscallResult {
        SyscallResult::new(self.frame.result().0 as i64)
    }
    fn set_result(&mut self, result: SyscallResult) {
        self.frame
            .set_result(carrick_guest_arch::NativeReturnWord(result.raw() as u64));
    }
}

impl<
    'a,
    F: Fn(u32) -> *mut u8,
    C: ThreadCpu,
    U: UserWord,
    G: GuestDispatchFrame,
    Context: super::dispatch::DispatchContext,
> carrick_personality_linux::identity::IdentityNative<'a>
    for El1PendingFamilies<'a, F, C, U, G, Context>
{
    fn arguments(&self) -> [u64; 6] {
        [
            self.frame.argument(0).unwrap_or(0),
            self.frame.argument(1).unwrap_or(0),
            self.frame.argument(2).unwrap_or(0),
            self.frame.argument(3).unwrap_or(0),
            self.frame.argument(4).unwrap_or(0),
            self.frame.argument(5).unwrap_or(0),
        ]
    }
    fn visible_tid(&self) -> Option<u32> {
        let binding = LifecycleNative::binding(self)?;
        let process = self.process.as_deref()?;
        if process.binding() != binding {
            return None;
        }
        self.thread()?.slot.visible_tid()
    }
    fn set_clear_child_tid(&mut self, address: u64) -> bool {
        let Some(thread) = self.thread() else {
            return false;
        };
        thread.slot.set_clear_child_tid(address);
        true
    }
    fn robust_list_for(&self, tid: i32) -> Result<(u64, u32), i64> {
        let thread = self
            .thread()
            .ok_or(carrick_personality_linux::identity::ESRCH)?;
        let cur_tid = thread.slot.visible_tid().unwrap_or(0);
        if tid == 0 || tid as u32 == cur_tid {
            Ok(thread.slot.robust_list())
        } else {
            Err(carrick_personality_linux::identity::ESRCH)
        }
    }
    fn process_identity(
        &mut self,
    ) -> Option<&mut dyn carrick_personality_linux::identity::ProcessIdentityVenue> {
        let binding = LifecycleNative::binding(self)?;
        let process = self.process.as_deref_mut()?;
        if process.binding() != binding {
            return None;
        }
        process.as_identity_venue()
    }
}

impl<
    'a,
    F: Fn(u32) -> *mut u8,
    C: ThreadCpu,
    U: UserWord,
    G: GuestDispatchFrame,
    Context: super::dispatch::DispatchContext,
> carrick_personality_linux::sysinfo::SysinfoNative<'a>
    for El1PendingFamilies<'a, F, C, U, G, Context>
{
    fn arguments(&self) -> [u64; 6] {
        [
            self.frame.argument(0).unwrap_or(0),
            self.frame.argument(1).unwrap_or(0),
            self.frame.argument(2).unwrap_or(0),
            self.frame.argument(3).unwrap_or(0),
            self.frame.argument(4).unwrap_or(0),
            self.frame.argument(5).unwrap_or(0),
        ]
    }
    fn process_sysinfo(
        &mut self,
    ) -> Option<&mut dyn carrick_personality_linux::sysinfo::ProcessSysinfoVenue> {
        let binding = LifecycleNative::binding(self)?;
        let process = self.process.as_deref_mut()?;
        if process.binding() != binding {
            return None;
        }
        process.as_sysinfo_venue()
    }
}

#[cfg(test)]
#[path = "lifecycle/tests.rs"]
mod tests;
