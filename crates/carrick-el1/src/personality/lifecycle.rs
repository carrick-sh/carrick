//! ARM native context and mapping hooks for the shared Linux lifecycle owner.
use super::dispatch::{El1PendingFamilies, GuestDispatchFrame, native_scheduler};
use super::sched::{ThreadCpu, UserWord};
pub use super::thread_setup::{GuestLifecycleVenue, LifecycleVenue, guest_venue};
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
        crate::file::UserCopy::copy_in(
            &mut crate::file::ValidatedCopy {
                task,
                validator: &crate::file::HardwareValidator,
            },
            dst,
            src.raw(),
        )
    }
    fn copy_out(&mut self, dst: UserVa, src: &[u8]) -> bool {
        #[cfg(test)]
        if let Some(user) = &mut self.lifecycle_user {
            return user.copy_out(dst.raw(), src);
        }
        if let Some(result) = self
            .process_venue()
            .and_then(|venue| venue.copy_out_owned(dst, src))
        {
            return result;
        }
        let Some(task) = self.current_tasks.get(self.frame.task_index()) else {
            return false;
        };
        crate::file::UserCopy::copy_out(
            &mut crate::file::ValidatedCopy {
                task,
                validator: &crate::file::HardwareValidator,
            },
            dst.raw(),
            src,
        )
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
    fn fail_lifecycle(&mut self, reason: carrick_el1_abi::NativeRunFailureReason) -> ! {
        let binding = LifecycleNative::binding(self).unwrap_or_else(|| {
            super::dispatch::invalid_completion(super::dispatch::NativeInvariant::EntryBinding)
        });
        super::native_run_failure::complete_native_run_failure(binding, reason)
    }
    fn lifecycle_admission_settled(&mut self) -> Result<(), i64> {
        if let Some(venue) = self.process_venue() {
            venue.lifecycle_admission_settled()?;
        }
        Ok(())
    }
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
    fn publish_born(&mut self, mut birth: ThreadBirth<'a, '_>) -> Result<(), i64> {
        let mut process = self.process.take();
        let result = if let Some(venue) = process.as_deref_mut() {
            if Some(venue.binding()) != LifecycleNative::binding(self) {
                Err(carrick_personality_linux::identity::ESRCH)
            } else if let Some(caller_tid) = birth.caller_tid {
                venue.thread_spawned(caller_tid, birth.child_tid, &mut || birth.record())
            } else {
                Err(carrick_personality_linux::identity::ESRCH)
            }
        } else {
            birth.record()
        };
        self.process = process;
        result?;
        // Credentials and Born are committed under the graph guard. Runnable
        // publication takes scheduler locks only after that guard is dropped.
        // The shared clone owner emits admission settlement only after this
        // enqueue. A terminal close wins against a prepublication claimant
        // under the graph guard; that caller instead rolls back live/claim
        // custody before publishing the settlement wake.
        self.enqueue_born(birth.record);
        Ok(())
    }
    fn thread_exited(&mut self, tid: u32) {
        if let Some(venue) = self.process_venue() {
            venue.thread_exited(tid);
        }
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
        // Registration and the positive tid are required by libc raise/abort.
        // CPL0 exit custody (shared-cpl0-thread-exit-clear-tid) still owes
        // exit-time clearing and the futex wake; ARM already honours both.
        let Some(thread) = self.thread() else {
            return false;
        };
        thread.slot.set_clear_child_tid(address);
        true
    }
    #[inline(never)]
    fn robust_list_for(&self, tid: i32) -> Result<(u64, u32), i64> {
        let thread = self
            .thread()
            .ok_or(carrick_personality_linux::identity::ESRCH)?;
        let cur_tid = thread.slot.visible_tid().unwrap_or(0);
        if tid == 0 || tid as u32 == cur_tid {
            return Ok(thread.slot.robust_list());
        }
        let target_tid = tid as u32;
        if let Some(process) = self.process.as_deref() {
            if Some(process.binding()) != LifecycleNative::binding(self) {
                return Err(carrick_personality_linux::identity::ESRCH);
            }
            return process.read_robust_list(target_tid, &mut |page, entry| {
                self.born_slot(page, entry)
                    .map(ThreadControlSlot::robust_list)
            });
        }
        if let Some(entry_ref) = thread.page.entry_ref_for_visible_tid(target_tid)
            && let Some(child_slot) = self.born_slot(thread.page, entry_ref)
        {
            return Ok(child_slot.robust_list());
        }
        Err(carrick_personality_linux::identity::ESRCH)
    }
    fn process_identity(
        &mut self,
    ) -> Option<&mut dyn carrick_personality_linux::identity::ProcessIdentityVenue> {
        let binding = LifecycleNative::binding(self)?;
        let tid = carrick_personality_linux::lifecycle::LifecycleNative::visible_tid(self)?;
        let process = self.process.as_deref_mut()?;
        if process.binding() != binding {
            return None;
        }
        process.set_calling_tid(tid);
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
        let tid = carrick_personality_linux::lifecycle::LifecycleNative::visible_tid(self)?;
        let process = self.process.as_deref_mut()?;
        if process.binding() != binding {
            return None;
        }
        process.set_calling_tid(tid);
        process.as_sysinfo_venue()
    }
}

impl<
    'a,
    F: Fn(u32) -> *mut u8,
    C: ThreadCpu,
    U: UserWord,
    G: GuestDispatchFrame,
    Context: super::dispatch::DispatchContext,
> carrick_personality_linux::signal::SignalNative<'a>
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

    fn process_signals(
        &mut self,
    ) -> Option<&mut dyn carrick_personality_linux::signal::ProcessSignals> {
        self.process.as_deref_mut().and_then(|p| p.signal_venue())
    }

    fn current_blocked(&self) -> carrick_signal_core::policy::SigBlockMask {
        let bits = self.thread().map(|t| t.slot.blocked().0).unwrap_or(0);
        carrick_signal_core::policy::SigBlockMask::blocking_all_of(
            carrick_signal_core::SignalSet::from_bits(bits),
        )
    }

    fn set_current_blocked(&mut self, mask: carrick_signal_core::policy::SigBlockMask) {
        if let Some(thread) = self.thread() {
            let new_mask =
                carrick_personality_linux::abi::thread::BlockedMask(mask.signals().bits());
            let _ = thread
                .slot
                .store_blocked_then_read_pending(new_mask, thread.slot.pending());
        }
    }

    fn current_pid(&self) -> u32 {
        self.process_pid().unwrap_or(0)
    }

    fn current_tid(&self) -> u32 {
        self.visible_tid()
            .or_else(|| self.process_pid())
            .unwrap_or(0)
    }

    fn restore_signal_frame(
        &mut self,
    ) -> Result<carrick_signal_core::policy::SigBlockMask, carrick_syscall_abi::LinuxErrno> {
        let task_idx = self.frame.task_index();
        #[cfg(test)]
        if let Some(user) = &mut self.lifecycle_user {
            struct Adapter<'u>(&'u mut (dyn crate::file::UserCopy + 'u));
            impl carrick_personality_linux::lifecycle::UserCopy for Adapter<'_> {
                fn copy_out(&mut self, dst: carrick_guest_arch::UserVa, src: &[u8]) -> bool {
                    self.0.copy_out(dst.raw(), src)
                }
                fn copy_in(&mut self, dst: &mut [u8], src: carrick_guest_arch::UserVa) -> bool {
                    self.0.copy_in(dst, src.raw())
                }
            }
            let mut adapter = Adapter(*user);
            return self.frame.restore_signal_frame(&mut adapter);
        }
        let Some(task) = self.current_tasks.get(task_idx) else {
            return Err(carrick_personality_linux::abi::signal::LINUX_EFAULT);
        };
        let mut copy = crate::file::ValidatedCopy {
            task,
            validator: &crate::file::HardwareValidator,
        };
        self.frame.restore_signal_frame(&mut copy)
    }
}

impl<V: crate::file::MemoryValidator> carrick_personality_linux::lifecycle::UserCopy
    for crate::file::ValidatedCopy<'_, V>
{
    fn copy_out(&mut self, dst: carrick_guest_arch::UserVa, src: &[u8]) -> bool {
        crate::file::UserCopy::copy_out(self, dst.raw(), src)
    }

    fn copy_in(&mut self, dst: &mut [u8], src: carrick_guest_arch::UserVa) -> bool {
        crate::file::UserCopy::copy_in(self, dst, src.raw())
    }
}

#[cfg(test)]
#[path = "lifecycle/tests.rs"]
mod tests;
