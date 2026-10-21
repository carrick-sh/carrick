//! Context switching, wait enrollment, timer expiration and CPU hardware.
use carrick_el1_abi::{
    Aarch64ParkedContext, Counters, CurrentTask, El1ExitReason, GIC_KICK_INTID, GIC_RESCHED_INTID,
    GIC_SPURIOUS_INTID, GIC_VTIMER_INTID, RecordId, SlotId, ThreadIdentity, TrapFrame, Waker,
    ZoneTables,
};
use carrick_sched_core::{IDLE_SPIN_NS, PREEMPT_SLICE_NS, ShortLockSpin, SwitchedIn, WakeEffects};
use core::sync::atomic::Ordering;

/// The earliest the virtual timer is armed from now: a deadline that could
/// not be served (a busy lock, a full run queue) is retried after this.
const TIMER_RETRY_NS: u64 = 50_000;

#[path = "sched/object_wait.rs"]
pub mod object_wait;

/// The CPU state and the per-vCPU hardware the in-guest scheduler uses.
pub trait ThreadCpu {
    /// Save the running thread's `frame` and live state into `ctx`.
    fn save(&mut self, frame: &TrapFrame, ctx: &mut Aarch64ParkedContext);
    /// Make `ctx` the running thread: fill `frame` and load live state.
    fn load(&mut self, frame: &mut TrapFrame, ctx: &Aarch64ParkedContext);
    /// ISA entry after a selected record is installed, before ERET.
    fn resume_lifecycle(
        &mut self,
        _zone: &ZoneTables,
        _task: &CurrentTask,
        _slot: SlotId,
        _record: RecordId,
    ) -> ResumeAction {
        ResumeAction::NoPending
    }
    /// Install translation roots (`TTBR0_EL1`, `TTBR1_EL1`), effective for
    /// everything after the call.
    fn set_translation(&mut self, ttbr0: u64, ttbr1: u64);
    /// Invalidate, on every PE, the stage-1 translations of the ASID in
    /// `ttbr0` (`TLBI ASIDE1IS`), complete before the call returns.
    fn invalidate_asid(&mut self, ttbr0: u64);
    /// The virtual counter (`CNTVCT_EL0`).
    fn now(&self) -> u64;
    /// The counter frequency (`CNTFRQ_EL0`), in Hz.
    fn freq(&self) -> u64;
    /// Arm the EL1 virtual timer at `cval` (`None`: disarm it).
    fn set_timer(&mut self, cval: Option<u64>);
    /// Write `ICC_SGI1R_EL1` (after making prior stores visible).
    fn send_sgi(&mut self, sgi1r: u64);
    /// Publish a scheduler reschedule to one issued CPU slot. `target` is the
    /// architecture's stored route; ARM retains its exact SGI encoding.
    fn send_resched(&mut self, slot: SlotId, target: u64) {
        if target == carrick_sched_core::HOST_RESCHEDULE_TARGET {
            #[cfg(all(target_os = "none", target_arch = "aarch64"))]
            if crate::isa::aarch64::cross_hvc_residency_kick(slot).is_err() {
                hw::fatal_entry_binding();
            }
            #[cfg(not(all(target_os = "none", target_arch = "aarch64")))]
            {
                let _ = slot;
                self.send_sgi(target);
            }
            return;
        }
        self.send_sgi(target | (u64::from(GIC_RESCHED_INTID) << 24));
    }
    /// Acknowledge the highest-priority pending interrupt (`ICC_IAR1_EL1`);
    /// [`GIC_SPURIOUS_INTID`] when none is pending.
    fn ack_irq(&mut self) -> u32;
    /// Complete `intid` (`ICC_EOIR1_EL1`).
    fn end_irq(&mut self, intid: u32);
    /// Wait for an interrupt (`WFI`), with IRQs masked at EL1: a pending
    /// interrupt ends the wait, and it may also end early.
    fn wait_for_interrupt(&mut self);
    /// Host-test rendezvous at the last idle boundary before WFI.
    #[cfg(any(test, feature = "host-test"))]
    fn before_idle_wfi(&mut self) {}
    /// One iteration of an idle poll.
    fn spin(&mut self);
    /// This vCPU's `ICC_SGI1R_EL1` routing bits, from `MPIDR_EL1`.
    fn own_sgi_target(&self) -> u64;
}

/// Scheduler effect of the native owner resume checkpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResumeAction {
    NoPending,
    Returned(carrick_guest_arch::NativeReturnWord),
    Left,
}

enum LoadResult {
    Running,
    NeedsHost,
    Left,
}

/// Reads guest user memory.
pub trait UserWord {
    /// The 32-bit word at `uaddr`, or `None` if EL0 cannot read it.
    fn read_u32(&self, task: &CurrentTask, uaddr: u64) -> Option<u32>;
    /// The 64-bit word at `uaddr`, or `None` if EL0 cannot read it.
    fn read_u64(&self, task: &CurrentTask, uaddr: u64) -> Option<u64>;
}

pub use carrick_guest_arch::sgi_target_of;

/// The running thread's identity, as the host published it (for the
/// host-loaded thread) or EL1 did after a switch.
pub fn identity_of(task: &CurrentTask, affinity: u64) -> ThreadIdentity {
    ThreadIdentity {
        tid: task.execution.task.load(Ordering::Relaxed),
        serial: task.mm.thread_generation.load(Ordering::Relaxed),
        mm: task.mm.key.load(Ordering::Relaxed),
        file_table: task.linux.file_table.load(Ordering::Relaxed),
        generation: task.execution.generation.load(Ordering::Relaxed).raw(),
        affinity_source: task.lifecycle_refs().map_or(
            carrick_sched_core::AffinitySource::UNBOUND,
            |(_, control)| control.affinity_source(),
        ),
        affinity,
        lifecycle_page: task.metadata.lifecycle_page.load(Ordering::Acquire),
        control_slot: task.metadata.control_slot.load(Ordering::Acquire),
    }
}

/// Publish the switched-in thread as the slot's running task (its process
/// too: EL1 may have switched the vCPU to another address space).
fn publish_identity(task: &CurrentTask, id: ThreadIdentity) {
    task.execution.task.store(id.tid, Ordering::Relaxed);
    task.mm
        .thread_generation
        .store(id.serial, Ordering::Relaxed);
    task.linux
        .file_table
        .store(id.file_table, Ordering::Relaxed);
    task.mm.key.store(id.mm, Ordering::Relaxed);
    task.publish_lifecycle(id.lifecycle_page, id.control_slot);
    task.execution.generation.store(
        carrick_el1_abi::SnapshotGeneration::from_raw(id.generation),
        Ordering::Release,
    );
}

/// How a futex syscall EL1 served ended.
pub use carrick_core::Served;

/// What the in-guest scheduler works with on one vCPU slot.
pub struct Sched<'a, C: ThreadCpu, U: UserWord> {
    pub zone: &'a ZoneTables,
    pub slot: SlotId,
    pub task: &'a CurrentTask,
    pub cpu: &'a mut C,
    pub user: &'a U,
    pub counters: &'a Counters,
    pub handoff: Option<&'a mut Option<carrick_el1_abi::EntryHandoffReceipt<Aarch64ParkedContext>>>,
}

/// What [`Sched::take_irqs`] acknowledged.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct IrqsTaken {
    pub kick: bool,
    pub timer: bool,
    pub resched: bool,
}

impl<C: ThreadCpu, U: UserWord> Sched<'_, C, U> {
    pub(crate) fn record_handoff(
        &mut self,
        receipt: Option<carrick_el1_abi::EntryHandoffReceipt<Aarch64ParkedContext>>,
    ) {
        if let Some(destination) = self.handoff.as_deref_mut() {
            *destination = receipt;
        }
    }
    fn current_record(&self) -> Result<carrick_el1_abi::RecordId, carrick_sched_core::Exhausted> {
        let record = self.zone.current_or_new(
            self.slot,
            identity_of(self.task, self.zone.slot(self.slot).affinity()),
        )?;
        #[cfg(target_os = "none")]
        if let Some((_, slot)) = self.task.lifecycle_refs() {
            slot.bind_zone_record(self.zone.record_ref(record));
        }
        Ok(record)
    }
    pub fn ticks(&self, ns: u64) -> u64 {
        (u128::from(ns) * u128::from(self.cpu.freq()) / 1_000_000_000) as u64
    }

    pub fn wake_word(
        &mut self,
        frame: &mut TrapFrame,
        mm: u64,
        uaddr: u64,
        bitset: u32,
        count: u32,
    ) -> Option<Served> {
        let (zone, slot) = (self.zone, self.slot);
        let was_empty = zone.slot(slot).queued() == 0;
        let guard = zone.short_lock(
            ZoneTables::bucket_of_with_context(mm, uaddr),
            &ShortLockSpin,
        );
        let mut effects = WakeEffects::default();
        let n = zone
            .wake_placed(
                &guard,
                mm,
                uaddr,
                bitset,
                count,
                Waker::El1 { slot },
                &mut [],
                &mut effects,
            )
            .ok()?;
        drop(guard);
        self.send_sgis(&effects);
        if effects.queued_own && was_empty {
            zone.note_queued_since(slot, self.cpu.now());
        }
        if effects.misplaced {
            // A woken thread sits here but may not run here: the exit this
            // causes hands it to the host, which places it.
            self.task.linux.mark_pending_host_work();
        }
        if effects.queued_own {
            self.program_timer(true);
        }
        frame.x[0] = u64::from(n);
        Some(Served::Returned { switched: false })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn wait_word(
        &mut self,
        frame: &mut TrapFrame,
        mm: u64,
        uaddr: u64,
        bitset: u32,
        expected: u32,
        deadline: Option<u64>,
        mismatch_result: u64,
        timeout_result: u64,
    ) -> Option<Served> {
        let (zone, slot) = (self.zone, self.slot);
        let guard = zone.short_lock(
            ZoneTables::bucket_of_with_context(mm, uaddr),
            &ShortLockSpin,
        );
        let Some(word) = self.user.read_u32(self.task, uaddr) else {
            drop(guard);
            return None;
        };
        if word != expected {
            drop(guard);
            frame.x[0] = mismatch_result;
            return Some(Served::Returned { switched: false });
        }
        let fresh = zone.slot(slot).current().is_none();
        let record = self.current_record().ok()?;
        let Some(start) = carrick_core::entry::prepare_handoff(
            carrick_core::entry::binding(&self.task.execution, &self.task.mm),
            carrick_el1_abi::BornInZoneSource { zone, slot },
            record,
        ) else {
            drop(guard);
            if fresh {
                zone.discard_unpublished(slot, record);
            }
            return None;
        };
        // SAFETY: this vCPU runs the thread `record` holds (a fresh home
        // record, or the switched-in `OnCpu` one); nobody else may touch it
        // until the park below is published.
        self.cpu
            .save(frame, unsafe { zone.record(record).ctx_mut() });
        let seq = zone.next_seq(record);
        // Reserve one exact record lease before publishing its timed park.
        if deadline.is_some() && zone.arm_timer(slot, record, seq).is_err() {
            drop(guard);
            if fresh {
                zone.discard_unpublished(slot, record);
            }
            return None;
        }
        if zone
            .enqueue(&guard, record, seq, mm, uaddr, bitset, 0)
            .is_err()
        {
            zone.cancel_timer_admission(zone.record_ref(record));
            drop(guard);
            if fresh {
                zone.discard_unpublished(slot, record);
            }
            return None;
        }
        zone.set_deadline(record, deadline.unwrap_or(0));
        let receipt = carrick_core::entry::publish_handoff_park(
            start,
            &guard,
            carrick_el1_abi::EntryRecordGeneration(seq),
        );
        if receipt.is_none() {
            drop(guard);
            if fresh {
                zone.discard_unpublished(slot, record);
            }
            return None;
        }
        drop(guard);
        self.record_handoff(receipt);
        zone.clear_current(slot);
        zone.counters.el1_parks.fetch_add(1, Ordering::Relaxed);
        Some(self.run_next(frame, timeout_result))
    }

    /// The running thread parked (or exited in the zone): run the next
    /// runnable thread, or leave for the host when that thread needs its
    /// executor, or idle.
    pub fn run_next(&mut self, frame: &mut TrapFrame, timeout_result: u64) -> Served {
        match self.run_ready(frame) {
            Some(progress) => progress,
            None => self.idle(frame, timeout_result),
        }
    }

    /// Consume already-ready zone work after an owned native park. No work
    /// leaves the caller's host handoff intact, so its execution capacity can
    /// be released without sending a native child to a host-task adopter.
    pub fn run_ready(&mut self, frame: &mut TrapFrame) -> Option<Served> {
        loop {
            if let Some(switched) = self.zone.switch_in_full(self.slot) {
                match self.load(frame, switched) {
                    LoadResult::Running => return Some(Served::Returned { switched: true }),
                    LoadResult::NeedsHost => return Some(self.service_exit()),
                    LoadResult::Left => continue,
                }
            }
            break;
        }
        if self.zone.head_needs_host(self.slot) {
            return Some(self.service_exit());
        }
        None
    }

    /// A thread EL1 just created (`clone`), unpublished and with the context
    /// its creator wrote, joins this vCPU's run queue: it runs when the
    /// running thread parks, when an idle vCPU steals it, or when the slice
    /// ends (the tick migrates it to an idle vCPU first).
    pub fn enqueue_born(&mut self, record: carrick_el1_abi::RecordId) {
        let (zone, slot) = (self.zone, self.slot);
        let was_empty = zone.slot(slot).queued() == 0;
        zone.requeue_preempted(slot, record);
        if was_empty {
            zone.note_queued_since(slot, self.cpu.now());
        }
        self.program_timer(true);
    }

    /// A guest yield is a fairness boundary for runnable work already owned
    /// by this EL1 zone. Save the caller's zero result before switching: the
    /// frame after the switch belongs to the sibling's suspended syscall.
    pub fn yield_queued(&mut self, frame: &mut TrapFrame) -> Option<Served> {
        if self.zone.runnable_head(self.slot).is_none()
            || self.task.linux.has_pending_host_work()
            || self.task.lifecycle_refs().is_some_and(|(page, control)| {
                page.pending().load().0 != 0 || control.pending().load().0 != 0
            })
        {
            return None;
        }
        let record = self.current_record().ok()?;
        let start = carrick_core::entry::prepare_handoff(
            carrick_core::entry::binding(&self.task.execution, &self.task.mm),
            carrick_el1_abi::BornInZoneSource {
                zone: self.zone,
                slot: self.slot,
            },
            record,
        )?;
        frame.x[0] = 0;
        let loaded = self.preempt_record(frame, record);
        if self.zone.slot(self.slot).current() == Some(record) {
            return Some(Served::Returned { switched: false });
        }
        let receipt = carrick_core::entry::publish_handoff_yield(start);
        self.record_handoff(receipt);
        if loaded {
            self.program_timer(true);
            Some(Served::Returned { switched: true })
        } else {
            Some(self.service_exit())
        }
    }

    /// The next thread on this vCPU needs its executor: leave for the host
    /// with no thread on the vCPU; the executor takes it from the run queue.
    fn service_exit(&mut self) -> Served {
        self.counters.exit_reasons[El1ExitReason::Service as usize].fetch_add(1, Ordering::Relaxed);
        self.zone
            .counters
            .el1_service_exits
            .fetch_add(1, Ordering::Relaxed);
        Served::Idle
    }

    /// Make the switched-in thread the running one, in its address space.
    /// `NeedsHost`: EL1 may not install that address space now (a pause of it is
    /// raised, or it is unpublished or retiring); the thread went back to
    /// the head of the run queue and the vCPU must leave for its executor
    /// ([`Self::service_exit`]), which loads it.
    fn load(&mut self, frame: &mut TrapFrame, switched: SwitchedIn) -> LoadResult {
        let (zone, slot) = (self.zone, self.slot);
        let rec = zone.record(switched.record);
        if !self.enter_space(rec.identity().mm) {
            zone.unswitch(slot, switched.record);
            return LoadResult::NeedsHost;
        }
        // SAFETY: switch_in_full made the record OnCpu on this slot.
        let ctx = unsafe { rec.ctx_mut() };
        publish_identity(self.task, rec.identity());
        let resumed = self
            .cpu
            .resume_lifecycle(zone, self.task, slot, switched.record);
        let result = match resumed {
            ResumeAction::Returned(result) => Some(result.0),
            ResumeAction::NoPending => switched.result,
            ResumeAction::Left => {
                self.leave_space();
                return LoadResult::Left;
            }
        };
        self.cpu.load(frame, ctx);
        self.task
            .linux
            .orig_arg0
            .store(ctx.native.x[0], Ordering::Relaxed);
        if let Some(result) = result {
            frame.x[0] = result;
        }
        if zone.slot(slot).queued() != 0 {
            zone.slot(slot).restart_slice(self.cpu.now());
        }
        self.program_timer(true);
        LoadResult::Running
    }

    /// Run address space `mm` on this vCPU. Nothing to do when it is the one
    /// installed. Otherwise the vCPU goes to the maintenance root first (so
    /// the slot's occupancy word never names a space other than the one its
    /// root translates), then publishes `mm` in the slot and reads `mm`'s
    /// gate ([`ZoneTables::install_space`], the installer's half of the
    /// Dekker pair with a page-table pause or ASID retirement), and only
    /// then installs `mm`'s roots, after invalidating its ASID if a
    /// foreign-COW publication is not yet covered.
    fn enter_space(&mut self, mm: u64) -> bool {
        let (zone, slot) = (self.zone, self.slot);
        if mm != 0 && zone.installed_space(slot) == mm {
            return true;
        }
        // Only for an executor with a task loaded: the idle entry runs no
        // thread itself (its executor loads it), and switches nothing.
        if mm == 0 || zone.spaces.idle_ttbr() == 0 || !zone.executor_has_task(slot) {
            return false;
        }
        // Only away from a published space (one root for both halves, the
        // default memory model: nothing an EL1 switch leaves behind), so the
        // host can settle the thread it loaded here with that space's roots.
        let installed = zone.installed_space(slot);
        if installed != 0 && zone.spaces.find(installed).is_none() {
            return false;
        }
        self.leave_space();
        let Some(grant) = zone.install_space(slot, mm) else {
            return false;
        };
        if let Some(published) = grant.cow_owed {
            self.cpu.invalidate_asid(grant.ttbr0);
            zone.spaces.cover_cow(grant.index, published);
            zone.counters
                .el1_cow_invalidations
                .fetch_add(1, Ordering::Relaxed);
        }
        self.cpu.set_translation(grant.ttbr0, grant.ttbr1);
        true
    }

    /// Run no address space on this vCPU: the maintenance root first, then
    /// the slot's occupancy word. A vCPU that idles in WFI holds no process's
    /// translations, so no pause of that process kicks it, and it walks no
    /// page table a retiring address space frees.
    fn leave_space(&mut self) {
        let (zone, slot) = (self.zone, self.slot);
        if zone.installed_space(slot) == 0 {
            return;
        }
        let idle = zone.spaces.idle_ttbr();
        if idle == 0 {
            return;
        }
        self.cpu.set_translation(idle, idle);
        zone.release_space(slot);
    }

    /// Nothing is runnable on this vCPU: poll, then park in WFI, until a
    /// thread is queued here (by another vCPU, or this vCPU's timer ending
    /// its timed park) or host work arrives.
    pub fn idle(&mut self, frame: &mut TrapFrame, timeout_result: u64) -> Served {
        let (zone, slot) = (self.zone, self.slot);
        zone.counters
            .el1_idle_entries
            .fetch_add(1, Ordering::Relaxed);
        zone.slot(slot).set_sgi_target(self.cpu.own_sgi_target());
        zone.enter_idle(slot, false);
        let spin_until = self.cpu.now().saturating_add(self.ticks(IDLE_SPIN_NS));
        loop {
            self.take_irqs();
            if self.task.linux.has_pending_host_work() || zone.slot(slot).affinity_excludes_cpu() {
                self.counters.exit_reasons[El1ExitReason::IdleHostWork as usize]
                    .fetch_add(1, Ordering::Relaxed);
                zone.leave_idle(slot);
                zone.counters.el1_idle_exits.fetch_add(1, Ordering::Relaxed);
                return Served::Idle;
            }
            let now = self.cpu.now();
            let _ = zone.expire_timer(slot, now, timeout_result);
            if let Some(switched) = zone.switch_in_full(slot).or_else(|| zone.steal(slot)) {
                zone.leave_idle(slot);
                match self.load(frame, switched) {
                    LoadResult::Running => return Served::Returned { switched: true },
                    LoadResult::NeedsHost => return self.service_exit(),
                    LoadResult::Left => {
                        zone.enter_idle(slot, false);
                        continue;
                    }
                }
            }
            if zone.head_needs_host(slot) {
                zone.leave_idle(slot);
                return self.service_exit();
            }
            if now < spin_until {
                self.cpu.spin();
                continue;
            }
            // Park on the maintenance root: a vCPU in WFI holds no process's
            // translations, so no pause or retirement of that process has
            // to wake it (the next thread it runs installs its own space).
            self.leave_space();
            if zone.enter_idle(slot, true) {
                self.program_timer(false);
                #[cfg(any(test, feature = "host-test"))]
                self.cpu.before_idle_wfi();
                // A host placement or handback can follow the last queue
                // scan while the slot is already IdleWfi. Its exit kick may
                // have arrived before this vCPU's next effective run. The
                // shared pending-work and owed-reschedule words are the
                // durable half of that wake; recheck them before WFI.
                if self.task.linux.has_pending_host_work()
                    || zone.slot(slot).affinity_excludes_cpu()
                    || zone.take_resched(slot)
                {
                    zone.enter_idle(slot, false);
                    continue;
                }
                zone.counters
                    .el1_wfi_entries
                    .fetch_add(1, Ordering::Relaxed);
                self.cpu.wait_for_interrupt();
                zone.enter_idle(slot, false);
            }
        }
    }

    /// Acknowledge and complete every pending interrupt: the host kick SGI
    /// becomes pending host work, the virtual timer is disarmed (whoever
    /// needs it re-arms it), a reschedule SGI only ends a wait.
    pub fn take_irqs(&mut self) -> IrqsTaken {
        let mut taken = IrqsTaken::default();
        loop {
            let intid = self.cpu.ack_irq();
            if intid == GIC_SPURIOUS_INTID {
                return taken;
            }
            if let Some(counter) = self.counters.irq_taken.get(intid as usize) {
                counter.fetch_add(1, Ordering::Relaxed);
            }
            match intid {
                GIC_KICK_INTID => {
                    self.task.linux.mark_pending_host_work();
                    taken.kick = true;
                }
                GIC_VTIMER_INTID => {
                    self.cpu.set_timer(None);
                    self.zone.slot(self.slot).set_timer_cval(0);
                    taken.timer = true;
                }
                GIC_RESCHED_INTID => taken.resched = true,
                _ => {}
            }
            self.cpu.end_irq(intid);
        }
    }

    /// An interrupt taken while EL0 ran on this vCPU. `Forward`: host work
    /// is pending, the vCPU leaves through the host at this EL0 boundary.
    pub fn interrupt(
        &mut self,
        frame: &mut TrapFrame,
        timeout_result: u64,
    ) -> carrick_el1_abi::Action {
        self.take_irqs();
        // A RESCHED receipt is only a prompt to inspect the CURRENT loaded
        // authority. A stale SGI cannot mark an allowed successor as owing work.
        if self.zone.slot(self.slot).affinity_excludes_cpu() {
            self.counters.exit_reasons[El1ExitReason::InterruptHostWork as usize]
                .fetch_add(1, Ordering::Relaxed);
            return carrick_el1_abi::Action::Forward;
        }
        if self.zone.current_affinity_excludes_cpu(self.slot) {
            if self.park_preempted(frame) {
                let mut effects = WakeEffects::default();
                self.zone.migrate_queued(self.slot, &mut effects);
                self.send_sgis(&effects);
                self.service_exit();
                return carrick_el1_abi::Action::Idle;
            }
            return carrick_el1_abi::Action::Forward;
        }
        if self.task.linux.has_pending_host_work() {
            self.counters.exit_reasons[El1ExitReason::InterruptHostWork as usize]
                .fetch_add(1, Ordering::Relaxed);
            return carrick_el1_abi::Action::Forward;
        }
        if self.task.mm.key.load(Ordering::Acquire) == 0 {
            return carrick_el1_abi::Action::Served;
        }
        let (zone, slot) = (self.zone, self.slot);
        let now = self.cpu.now();
        let _ = zone.expire_timer(slot, now, timeout_result);
        if zone.slot(slot).queued() != 0 {
            let mut since = zone.slot(slot).queued_since();
            if since == 0 {
                // Queued from another vCPU: the slice starts now.
                zone.slot(slot).restart_slice(now);
                since = now;
            }
            if now >= since.saturating_add(self.ticks(PREEMPT_SLICE_NS)) {
                let mut effects = WakeEffects::default();
                zone.migrate_queued(slot, &mut effects);
                self.send_sgis(&effects);
                if zone.head_needs_host(slot) {
                    // The next thread needs its executor: the running one
                    // goes to the tail of the run queue with its registers,
                    // and the vCPU leaves for the host with no thread on it.
                    if self.park_preempted(frame) {
                        self.service_exit();
                        return carrick_el1_abi::Action::Idle;
                    }
                } else if zone.slot(slot).queued() != 0 {
                    if !self.preempt(frame) {
                        // The head's address space could not be installed:
                        // the preempted thread is queued behind it and the
                        // vCPU leaves for the executor, which loads the head.
                        self.service_exit();
                        return carrick_el1_abi::Action::Idle;
                    }
                } else {
                    zone.slot(slot).restart_slice(now);
                }
            }
        }
        self.program_timer(true);
        carrick_el1_abi::Action::Served
    }

    /// The idle entry (EL1 plan 1d): the executor of this vCPU has no thread
    /// to load and started the vCPU in the scheduler. Run a queued thread
    /// (`Served`: the frame is now that thread's), or leave for the host
    /// (`Idle`): host work arrived, or the next thread needs its executor.
    pub fn idle_entry(
        &mut self,
        frame: &mut TrapFrame,
        timeout_result: u64,
    ) -> carrick_el1_abi::Action {
        self.take_irqs();
        if self.task.linux.has_pending_host_work()
            || self.zone.slot(self.slot).affinity_excludes_cpu()
        {
            self.counters.exit_reasons[El1ExitReason::IdleEntryHostWork as usize]
                .fetch_add(1, Ordering::Relaxed);
            return carrick_el1_abi::Action::Idle;
        }
        match self.idle(frame, timeout_result) {
            Served::Returned { .. } => carrick_el1_abi::Action::Served,
            Served::Idle => carrick_el1_abi::Action::Idle,
        }
    }

    /// Preempt the running thread into its record at the tail of this
    /// vCPU's run queue, with nothing switched in (the next thread needs its
    /// executor). False if it could not be parked; it keeps running.
    fn park_preempted(&mut self, frame: &TrapFrame) -> bool {
        let (zone, slot) = (self.zone, self.slot);
        let Ok(prev) = self.current_record() else {
            return false;
        };
        // SAFETY: `prev` holds the running thread (a fresh home record, or
        // the switched-in OnCpu one): this vCPU is its only owner.
        self.cpu.save(frame, unsafe { zone.record(prev).ctx_mut() });
        zone.requeue_preempted(slot, prev);
        true
    }

    /// Preempt the running thread: it goes to the tail of this vCPU's run
    /// queue with its registers, and the head runs. False: the head's
    /// address space could not be installed; the vCPU must leave for its
    /// executor (both threads are queued).
    fn preempt(&mut self, frame: &mut TrapFrame) -> bool {
        if self.zone.runnable_head(self.slot).is_none() {
            return true;
        }
        let Ok(prev) = self.current_record() else {
            return true;
        };
        self.preempt_record(frame, prev)
    }

    fn preempt_record(&mut self, frame: &mut TrapFrame, prev: carrick_el1_abi::RecordId) -> bool {
        let (zone, slot) = (self.zone, self.slot);
        let fresh = zone.slot(slot).current().is_none();
        // SAFETY: `prev` holds the running thread (a fresh home record, or
        // the switched-in OnCpu one): this vCPU is its only owner.
        self.cpu.save(frame, unsafe { zone.record(prev).ctx_mut() });
        match zone.switch_in_full(slot) {
            Some(switched) => {
                zone.requeue_preempted(slot, prev);
                match self.load(frame, switched) {
                    LoadResult::Running => true,
                    LoadResult::NeedsHost => false,
                    LoadResult::Left => {
                        matches!(self.run_next(frame, 0), Served::Returned { switched: true })
                    }
                }
            }
            None => {
                // The head changed under us (it cannot: only this vCPU takes
                // from its queue). Keep running `prev`.
                if fresh {
                    zone.discard_unpublished(slot, prev);
                }
                true
            }
        }
    }

    /// Arm this vCPU's virtual timer for what it must next do: end this
    /// vCPU's timed park, and (while a thread `running` here has others
    /// queued behind it) end its slice.
    fn program_timer(&mut self, running: bool) {
        let (zone, slot) = (self.zone, self.slot);
        let s = zone.slot(slot);
        let mut want = zone.timer_deadline(slot);
        if running && s.queued() != 0 {
            let mut since = s.queued_since();
            if since == 0 {
                since = self.cpu.now();
                s.restart_slice(since);
            }
            let slice_end = since.saturating_add(self.ticks(PREEMPT_SLICE_NS));
            want = Some(want.map_or(slice_end, |deadline| deadline.min(slice_end)));
        }
        // Nothing to time: a timer still armed fires once, finds nothing to
        // do and is disarmed then (`take_irqs`), which is cheaper than a
        // disarm on every switch.
        let Some(mut cval) = want else {
            return;
        };
        // A deadline already past means the timeout could not be taken yet
        // (a busy bucket lock, a full run queue): retry shortly rather than
        // take the interrupt again at once.
        let now = self.cpu.now();
        if cval <= now {
            cval = now.saturating_add(self.ticks(TIMER_RETRY_NS));
        }
        // An armed timer due earlier re-programs this one when it fires.
        let armed = s.timer_cval();
        if armed == 0 || cval < armed {
            self.cpu.set_timer(Some(cval));
            s.set_timer_cval(cval);
        }
    }

    fn send_sgis(&mut self, effects: &WakeEffects) {
        for slot in effects.sgi_slots() {
            let target = self.zone.slot(slot).sgi_target();
            if target == 0 {
                continue;
            }
            self.cpu.send_resched(slot, target);
            self.zone.counters.el1_sgis.fetch_add(1, Ordering::Relaxed);
        }
    }
}

#[path = "sched/hw.rs"]
pub mod hw;
#[cfg(target_os = "none")]
pub use hw::HardwareCpu;
pub use hw::HardwareUserWord;

/// The live system and FP/SIMD registers a switch moves, as plain fields.
#[cfg(any(test, feature = "host-test"))]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FakeRegs {
    pub sp_el0: u64,
    pub tpidr_el0: u64,
    pub tpidrro_el0: u64,
    pub contextidr_el1: u64,
    pub v: [u128; 32],
    pub fpsr: u64,
    pub fpcr: u64,
}

/// A host-test stand-in for the CPU: the registers a switch moves, plus a
/// model of the counter, the virtual timer and the GIC CPU interface.
#[cfg(any(test, feature = "host-test"))]
#[derive(Clone, Debug)]
pub struct FakeCpu {
    pub resume_once: Option<ResumeAction>,
    pub regs: FakeRegs,
    pub now: u64,
    pub freq: u64,
    /// Counter ticks one idle poll takes.
    pub spin_ticks: u64,
    /// The armed virtual timer.
    pub timer: Option<u64>,
    /// Interrupts pending besides the timer, in acknowledge order.
    pub pending: std::collections::VecDeque<u32>,
    pub sgis: std::vec::Vec<u64>,
    /// WFIs executed; a `WFI` with nothing to end it fails the test
    /// instead of hanging.
    pub wfis: u64,
    /// Coordinate a host publication after the idle slot entered WFI state.
    pub idle_gate: Option<std::sync::Arc<std::sync::Barrier>>,
    pub mpidr: u64,
    /// Negative control: a switch that forgets FP/SIMD.
    pub skip_fpsimd: bool,
    /// The installed translation roots (`TTBR0_EL1`, `TTBR1_EL1`).
    pub ttbr: (u64, u64),
    /// Every `set_translation`, in order.
    pub translations: std::vec::Vec<(u64, u64)>,
    /// Every `TLBI ASIDE1IS` operand (the TTBR0 value), in order.
    pub asid_invalidations: std::vec::Vec<u64>,
}

#[cfg(any(test, feature = "host-test"))]
impl Default for FakeCpu {
    fn default() -> Self {
        Self {
            resume_once: None,
            regs: FakeRegs::default(),
            now: 1_000_000,
            freq: 24_000_000,
            spin_ticks: 24,
            timer: None,
            pending: std::collections::VecDeque::new(),
            sgis: std::vec::Vec::new(),
            wfis: 0,
            idle_gate: None,
            mpidr: 0x8000_0003,
            skip_fpsimd: false,
            ttbr: (0, 0),
            translations: std::vec::Vec::new(),
            asid_invalidations: std::vec::Vec::new(),
        }
    }
}

#[cfg(any(test, feature = "host-test"))]
impl ThreadCpu for FakeCpu {
    fn before_idle_wfi(&mut self) {
        if let Some(gate) = self.idle_gate.take() {
            gate.wait();
            gate.wait();
        }
    }
    fn resume_lifecycle(
        &mut self,
        zone: &ZoneTables,
        _: &CurrentTask,
        slot: SlotId,
        _: RecordId,
    ) -> ResumeAction {
        let action = self.resume_once.take().unwrap_or(ResumeAction::NoPending);
        if matches!(action, ResumeAction::Left) {
            zone.clear_current(slot);
        }
        action
    }
    fn save(&mut self, frame: &TrapFrame, ctx: &mut Aarch64ParkedContext) {
        let ctx = &mut ctx.native;
        hw::save_frame(frame, ctx);
        ctx.sp_el0 = self.regs.sp_el0;
        ctx.tpidr_el0 = self.regs.tpidr_el0;
        ctx.tpidrro_el0 = self.regs.tpidrro_el0;
        ctx.contextidr_el1 = self.regs.contextidr_el1;
        if !self.skip_fpsimd {
            ctx.v = self.regs.v;
            ctx.fpsr = self.regs.fpsr;
            ctx.fpcr = self.regs.fpcr;
        }
    }

    fn load(&mut self, frame: &mut TrapFrame, ctx: &Aarch64ParkedContext) {
        let ctx = &ctx.native;
        hw::load_frame(frame, ctx);
        self.regs.sp_el0 = ctx.sp_el0;
        self.regs.tpidr_el0 = ctx.tpidr_el0;
        self.regs.tpidrro_el0 = ctx.tpidrro_el0;
        self.regs.contextidr_el1 = ctx.contextidr_el1;
        if !self.skip_fpsimd {
            self.regs.v = ctx.v;
            self.regs.fpsr = ctx.fpsr;
            self.regs.fpcr = ctx.fpcr;
        }
    }

    fn set_translation(&mut self, ttbr0: u64, ttbr1: u64) {
        self.ttbr = (ttbr0, ttbr1);
        self.translations.push((ttbr0, ttbr1));
    }

    fn invalidate_asid(&mut self, ttbr0: u64) {
        self.asid_invalidations.push(ttbr0);
    }

    fn now(&self) -> u64 {
        self.now
    }

    fn freq(&self) -> u64 {
        self.freq
    }

    fn set_timer(&mut self, cval: Option<u64>) {
        self.timer = cval;
    }

    fn send_sgi(&mut self, sgi1r: u64) {
        self.sgis.push(sgi1r);
    }

    fn ack_irq(&mut self) -> u32 {
        if self.timer.is_some_and(|cval| self.now >= cval) {
            return GIC_VTIMER_INTID;
        }
        self.pending.pop_front().unwrap_or(GIC_SPURIOUS_INTID)
    }

    fn end_irq(&mut self, _intid: u32) {}

    fn wait_for_interrupt(&mut self) {
        self.wfis += 1;
        if !self.pending.is_empty() {
            return;
        }
        match self.timer {
            Some(cval) => self.now = self.now.max(cval),
            None => panic!("WFI with no timer and no interrupt: the vCPU would sleep forever"),
        }
    }

    fn spin(&mut self) {
        self.now += self.spin_ticks;
    }

    fn own_sgi_target(&self) -> u64 {
        sgi_target_of(self.mpidr)
    }
}
