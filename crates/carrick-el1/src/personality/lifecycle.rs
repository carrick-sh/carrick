//! ARM native context and mapping hooks for the shared Linux lifecycle owner.
use super::dispatch::{El1PendingFamilies, native_scheduler};
use super::sched::{ThreadCpu, UserWord};
pub use super::thread_setup::{GuestLifecycleVenue, LifecycleVenue, guest_venue};
use crate::file::UserCopy as ArmUserCopy;
use carrick_el1_abi::EntryMmKey;
use carrick_el1_abi::{
    Claim, EntryRef, LifecycleDecline, RecordRef, SlotId, ThreadControlSlot, ThreadCtx,
    ThreadIdentity, ThreadLifecyclePage,
};
use carrick_guest_arch::UserVa;
use carrick_personality_linux::abi::entry::LinuxTaskState;
use carrick_personality_linux::abi::entry::SyscallResult;
pub use carrick_personality_linux::lifecycle::*;
pub use carrick_personality_linux::thread::{LifecycleThread, SYS_SET_ROBUST_LIST};

impl<F: Fn(u32) -> *mut u8, C: ThreadCpu, U: UserWord> UserCopy
    for El1PendingFamilies<'_, F, C, U>
{
    fn copy_in(&mut self, dst: &mut [u8], src: u64) -> bool {
        #[cfg(test)]
        if let Some(user) = &mut self.lifecycle_user {
            return user.copy_in(dst, src);
        }
        let Some(task) = self.current_tasks.get(self.frame.slot as usize) else {
            return false;
        };
        crate::file::ValidatedCopy {
            task,
            validator: &crate::file::HardwareValidator,
        }
        .copy_in(dst, src)
    }
    fn copy_out(&mut self, dst: u64, src: &[u8]) -> bool {
        #[cfg(test)]
        if let Some(user) = &mut self.lifecycle_user {
            return user.copy_out(dst, src);
        }
        let Some(task) = self.current_tasks.get(self.frame.slot as usize) else {
            return false;
        };
        crate::file::ValidatedCopy {
            task,
            validator: &crate::file::HardwareValidator,
        }
        .copy_out(dst, src)
    }
}

impl<'a, F: Fn(u32) -> *mut u8, C: ThreadCpu, U: UserWord> LifecycleNative<'a>
    for El1PendingFamilies<'a, F, C, U>
{
    fn arguments(&self) -> [u64; 6] {
        [
            self.frame.x[0],
            self.frame.x[1],
            self.frame.x[2],
            self.frame.x[3],
            self.frame.x[4],
            self.frame.x[5],
        ]
    }
    fn binding(&self) -> Option<carrick_el1_abi::ExecutionBinding> {
        self.current_tasks
            .get(self.frame.slot as usize)
            .map(super::common_entry::execution_binding)
    }
    fn task_state(&self) -> Option<&'a LinuxTaskState> {
        self.current_tasks
            .get(self.frame.slot as usize)
            .map(|task| &task.linux)
    }
    fn thread(&self) -> Option<LifecycleThread<'a>> {
        self.lifecycle?
            .thread(self.current_tasks.get(self.frame.slot as usize)?)
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
        self.zone.is_some() && SlotId::from_index(self.frame.slot as usize).is_some()
    }
    fn user_sp(&mut self) -> Option<UserVa> {
        let zone = self.zone.as_mut()?;
        let mut scratch = ThreadCtx::ZERO;
        zone.cpu.save(self.frame, &mut scratch);
        Some(UserVa::new(scratch.sp_el0))
    }
    fn affinity(&self) -> Option<u64> {
        let zone = self.zone.as_ref()?.tables;
        let slot = SlotId::from_index(self.frame.slot as usize)?;
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
        zone.cpu.save(self.frame, ctx);
        ctx.x[0] = 0;
        ctx.sp_el0 = context.stack.raw();
        if let Some(tls) = context.tls {
            ctx.tpidr_el0 = tls.raw();
        }
        // AArch64 Linux vDSO identity packing is specific to this native ABI.
        if ctx.tpidrro_el0 != 0 {
            ctx.tpidrro_el0 = (ctx.tpidrro_el0 & !0xffff_ffff) | u64::from(context.visible_tid);
        }
    }
    fn enqueue_born(&mut self, record: RecordRef) {
        let Some(task) = self.current_tasks.get(self.frame.slot as usize) else {
            return;
        };
        let Some(slot) = SlotId::from_index(self.frame.slot as usize) else {
            return;
        };
        let Some(zone) = &mut self.zone else {
            return;
        };
        if zone.tables.record(record.id).incarnation() == record.incarnation {
            native_scheduler(zone, task, self.counters, slot).enqueue_born(record.id);
        }
    }
    fn exit_record(&self) -> Option<ExitRecord> {
        let zone = self.zone.as_ref()?.tables;
        let slot = SlotId::from_index(self.frame.slot as usize)?;
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
        let Some(task) = self.current_tasks.get(self.frame.slot as usize) else {
            return false;
        };
        let Some(slot) = SlotId::from_index(self.frame.slot as usize) else {
            return false;
        };
        let Some(zone) = &mut self.zone else {
            return false;
        };
        native_scheduler(zone, task, self.counters, slot)
            .wake_word(
                self.frame,
                mm.raw(),
                address.raw(),
                carrick_personality_linux::thread::CHILD_TID_WAKE_MASK,
                carrick_personality_linux::thread::CHILD_TID_WAKE_COUNT,
            )
            .is_some()
    }
    fn release_current(&mut self, record: RecordRef) {
        if let (Some(zone), Some(slot)) = (&self.zone, SlotId::from_index(self.frame.slot as usize))
            && zone.tables.live(record).is_some()
        {
            let _ = zone.tables.release_current(
                slot,
                record.id,
                &carrick_sched_core::BoundedSpin(carrick_el1_abi::EL1_GUEST_LOCK_SPINS),
            );
        }
    }
    fn run_next(&mut self, timeout_result: SyscallResult) -> (carrick_core::Served, SyscallResult) {
        let Some(task) = self.current_tasks.get(self.frame.slot as usize) else {
            return (
                carrick_core::Served::Idle,
                SyscallResult::new(self.frame.x[0] as i64),
            );
        };
        let Some(slot) = SlotId::from_index(self.frame.slot as usize) else {
            return (
                carrick_core::Served::Idle,
                SyscallResult::new(self.frame.x[0] as i64),
            );
        };
        let Some(zone) = &mut self.zone else {
            return (
                carrick_core::Served::Idle,
                SyscallResult::new(self.frame.x[0] as i64),
            );
        };
        let served = native_scheduler(zone, task, self.counters, slot)
            .run_next(self.frame, timeout_result.raw() as u64);
        (served, SyscallResult::new(self.frame.x[0] as i64))
    }
    fn result(&self) -> SyscallResult {
        SyscallResult::new(self.frame.x[0] as i64)
    }
    fn set_result(&mut self, result: SyscallResult) {
        self.frame.x[0] = result.raw() as u64;
    }
}

#[cfg(test)]
#[path = "lifecycle/tests.rs"]
mod tests;
