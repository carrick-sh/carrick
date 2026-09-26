//! The in-guest scheduler (EL1 plans 1b and 1c).
//!
//! EL1 serves `FUTEX_WAKE(_BITSET)_PRIVATE`, untimed
//! `FUTEX_WAIT(_BITSET)_PRIVATE` and, for the thread the host loaded on this
//! vCPU, `FUTEX_WAIT_PRIVATE` with a relative timeout, for a zone process, on
//! the zone tables it shares with the host (`carrick_sched_core`):
//!
//! - a wake claims parked waiters of the same process and queues each where
//!   it may run (`ZoneTables::wake_placed`): a thread the host loaded on some
//!   vCPU goes back to that vCPU, any other to an idle vCPU of the process,
//!   else to this vCPU's own run queue. A vCPU running a thread or parked in
//!   WFI gets a reschedule SGI;
//! - a wait parks the running thread and switches the vCPU to the next
//!   runnable thread: register state, `SP_EL0`, the thread pointers,
//!   `CONTEXTIDR_EL1` and FP/SIMD are saved to the parked record and loaded
//!   from the next one, with no host exit. With nothing runnable the vCPU
//!   idles in EL1: it polls its run queue for [`IDLE_SPIN_NS`], then parks in
//!   WFI until an SGI, its virtual timer or a host kick;
//! - an interrupt taken at EL0 ([`Sched::serve_irq`]): the virtual timer ends
//!   this vCPU's timed park and preempts the running thread when a queued
//!   one has waited [`PREEMPT_SLICE_NS`] (after moving what it can to idle
//!   vCPUs); a reschedule SGI makes this vCPU look at its run queue; the host
//!   kick SGI sends the vCPU to the host.
//!
//! Everything else is forwarded: timeouts of switched-in threads, absolute
//! or `FUTEX_CLOCK_REALTIME` timeouts, requeue, `futex_waitv`, shared
//! futexes, a busy bucket, a wake EL1 cannot place, a fault on the futex
//! word. While threads are queued on this vCPU, any other syscall is
//! forwarded too, so the host takes them at that exit.

use carrick_el1_abi::{
    Counters, CurrentTask, GIC_KICK_INTID, GIC_RESCHED_INTID, GIC_SPURIOUS_INTID, GIC_VTIMER_INTID,
    RecordId, SlotId, ThreadCtx, ThreadIdentity, TrapFrame, Waker, ZoneTables,
};
use carrick_sched_core::{
    BoundedSpin, IDLE_SPIN_NS, PREEMPT_SLICE_NS, SwitchedIn, WakeEffects, ZONE_RUNQ_CAPACITY,
};
use core::sync::atomic::Ordering;

pub const SYS_FUTEX: usize = 98;
const FUTEX_WAIT_PRIVATE: u64 = 128;
const FUTEX_WAKE_PRIVATE: u64 = 129;
const FUTEX_WAIT_BITSET_PRIVATE: u64 = 128 | 9;
const FUTEX_WAKE_BITSET_PRIVATE: u64 = 128 | 10;
const EAGAIN: i64 = -11;

/// Bucket-lock spins before EL1 gives up and forwards.
const EL1_ZONE_LOCK_SPINS: u32 = 1024;

/// The earliest the virtual timer is armed from now: a deadline that could
/// not be served (a busy lock, a full run queue) is retried after this.
const TIMER_RETRY_NS: u64 = 50_000;

/// Whether `frame` is a futex operation EL1 may serve (the rest forward).
/// A relative `FUTEX_WAIT_PRIVATE` timeout is servable here; whether this
/// thread's timeout is, [`Sched::serve_futex`] decides.
pub fn is_served_futex_op(frame: &TrapFrame) -> bool {
    if frame.x[8] as usize != SYS_FUTEX || frame.x[0] & 3 != 0 {
        return false;
    }
    match frame.x[1] {
        FUTEX_WAIT_PRIVATE => true,
        FUTEX_WAIT_BITSET_PRIVATE => frame.x[3] == 0 && frame.x[5] as u32 != 0,
        FUTEX_WAKE_PRIVATE => (frame.x[2] as i32) > 0,
        FUTEX_WAKE_BITSET_PRIVATE => (frame.x[2] as i32) > 0 && frame.x[5] as u32 != 0,
        _ => false,
    }
}

/// The CPU state and the per-vCPU hardware the in-guest scheduler uses.
pub trait ThreadCpu {
    /// Save the running thread's `frame` and live state into `ctx`.
    fn save(&mut self, frame: &TrapFrame, ctx: &mut ThreadCtx);
    /// Make `ctx` the running thread: fill `frame` and load live state.
    fn load(&mut self, frame: &mut TrapFrame, ctx: &ThreadCtx);
    /// The virtual counter (`CNTVCT_EL0`).
    fn now(&self) -> u64;
    /// The counter frequency (`CNTFRQ_EL0`), in Hz.
    fn freq(&self) -> u64;
    /// Arm the EL1 virtual timer at `cval` (`None`: disarm it).
    fn set_timer(&mut self, cval: Option<u64>);
    /// Write `ICC_SGI1R_EL1` (after making prior stores visible).
    fn send_sgi(&mut self, sgi1r: u64);
    /// Acknowledge the highest-priority pending interrupt (`ICC_IAR1_EL1`);
    /// [`GIC_SPURIOUS_INTID`] when none is pending.
    fn ack_irq(&mut self) -> u32;
    /// Complete `intid` (`ICC_EOIR1_EL1`).
    fn end_irq(&mut self, intid: u32);
    /// Wait for an interrupt (`WFI`), with IRQs masked at EL1: a pending
    /// interrupt ends the wait, and it may also end early.
    fn wait_for_interrupt(&mut self);
    /// One iteration of an idle poll.
    fn spin(&mut self);
    /// This vCPU's `ICC_SGI1R_EL1` routing bits, from `MPIDR_EL1`.
    fn own_sgi_target(&self) -> u64;
}

/// Reads guest user memory.
pub trait UserWord {
    /// The 32-bit word at `uaddr`, or `None` if EL0 cannot read it.
    fn read_u32(&self, task: &CurrentTask, uaddr: u64) -> Option<u32>;
    /// The 64-bit word at `uaddr`, or `None` if EL0 cannot read it.
    fn read_u64(&self, task: &CurrentTask, uaddr: u64) -> Option<u64>;
}

/// `ICC_SGI1R_EL1` routing bits for a CPU with affinity `mpidr`: Aff3, Aff2
/// and Aff1 in place, the target-list bit and range selector of Aff0.
pub const fn sgi_target_of(mpidr: u64) -> u64 {
    let aff0 = mpidr & 0xff;
    let aff1 = (mpidr >> 8) & 0xff;
    let aff2 = (mpidr >> 16) & 0xff;
    let aff3 = (mpidr >> 32) & 0xff;
    (1 << (aff0 & 0xf)) | ((aff0 >> 4) << 44) | (aff1 << 16) | (aff2 << 32) | (aff3 << 48)
}

/// The running thread's identity, as the host published it (for the
/// host-loaded thread) or EL1 did after a switch.
fn identity_of(task: &CurrentTask, affinity: u64) -> ThreadIdentity {
    ThreadIdentity {
        tid: task.task_id.load(Ordering::Relaxed),
        serial: task.thread_serial.load(Ordering::Relaxed),
        mm: task.zone_mm.load(Ordering::Relaxed),
        file_table: task.file_table.load(Ordering::Relaxed),
        generation: task.generation.load(Ordering::Relaxed),
        affinity,
    }
}

/// Publish the switched-in thread as the slot's running task.
fn publish_identity(task: &CurrentTask, id: ThreadIdentity) {
    task.task_id.store(id.tid, Ordering::Relaxed);
    task.thread_serial.store(id.serial, Ordering::Relaxed);
    task.file_table.store(id.file_table, Ordering::Relaxed);
    task.generation.store(id.generation, Ordering::Release);
}

/// How a futex syscall EL1 served ended.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Served {
    /// The syscall returned; with `switched`, the caller parked and the vCPU
    /// now runs another thread: the frame and the slot's task record are
    /// that thread's.
    Returned { switched: bool },
    /// The caller parked, nothing was runnable, and host work arrived while
    /// the vCPU idled: it leaves through the host with no thread on it.
    Idle,
}

/// What the in-guest scheduler works with on one vCPU slot.
pub struct Sched<'a, C: ThreadCpu, U: UserWord> {
    pub zone: &'a ZoneTables,
    pub slot: SlotId,
    pub task: &'a CurrentTask,
    pub cpu: &'a mut C,
    pub user: &'a U,
    pub counters: &'a Counters,
}

/// What [`Sched::take_irqs`] acknowledged.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct IrqsTaken {
    pub kick: bool,
    pub timer: bool,
    pub resched: bool,
}

impl<C: ThreadCpu, U: UserWord> Sched<'_, C, U> {
    fn ticks(&self, ns: u64) -> u64 {
        (u128::from(ns) * u128::from(self.cpu.freq()) / 1_000_000_000) as u64
    }

    /// Serve a futex syscall at EL1, or `None` to forward it unchanged.
    pub fn serve_futex(&mut self, frame: &mut TrapFrame) -> Option<Served> {
        let mm = self.task.zone_mm.load(Ordering::Acquire);
        if mm == 0 || !is_served_futex_op(frame) {
            return None;
        }
        let uaddr = frame.x[0];
        match frame.x[1] {
            FUTEX_WAKE_PRIVATE | FUTEX_WAKE_BITSET_PRIVATE => self.serve_wake(frame, mm, uaddr),
            FUTEX_WAIT_PRIVATE | FUTEX_WAIT_BITSET_PRIVATE => self.serve_wait(frame, mm, uaddr),
            _ => None,
        }
    }

    fn serve_wake(&mut self, frame: &mut TrapFrame, mm: u64, uaddr: u64) -> Option<Served> {
        let (zone, slot) = (self.zone, self.slot);
        let bitset = if frame.x[1] == FUTEX_WAKE_PRIVATE {
            u32::MAX
        } else {
            frame.x[5] as u32
        };
        let count = frame.x[2] as i32 as u32;
        let was_empty = zone.slot(slot).queued() == 0;
        let guard = zone.lock(
            ZoneTables::bucket_of(mm, uaddr),
            &BoundedSpin(EL1_ZONE_LOCK_SPINS),
        )?;
        let mut woken = [RecordId::PLACEHOLDER; ZONE_RUNQ_CAPACITY];
        let mut effects = WakeEffects::default();
        let n = zone
            .wake_placed(
                &guard,
                mm,
                uaddr,
                bitset,
                count,
                Waker::El1 { slot },
                &mut woken,
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
            self.task.mark_pending_host_work();
        }
        if effects.queued_own {
            self.program_timer(true);
        }
        frame.x[0] = u64::from(n);
        Some(Served::Returned { switched: false })
    }

    fn serve_wait(&mut self, frame: &mut TrapFrame, mm: u64, uaddr: u64) -> Option<Served> {
        let (zone, slot) = (self.zone, self.slot);
        let bitset = if frame.x[1] == FUTEX_WAIT_PRIVATE {
            u32::MAX
        } else {
            frame.x[5] as u32
        };
        let expected = frame.x[2] as u32;
        // A timeout is served for the thread the host loaded on this vCPU
        // (its deadline is this vCPU's to keep, and the host takes it over
        // at an exit); a switched-in thread's timed wait forwards.
        let deadline = if frame.x[3] != 0 {
            let s = zone.slot(slot);
            if s.current().is_some() && s.current() != s.host_record() {
                return None;
            }
            let secs = self.user.read_u64(self.task, frame.x[3])? as i64;
            let nanos = self.user.read_u64(self.task, frame.x[3] + 8)? as i64;
            if secs < 0 || !(0..1_000_000_000).contains(&nanos) {
                return None;
            }
            let ticks = (secs as u64)
                .saturating_mul(self.cpu.freq())
                .saturating_add(self.ticks(nanos as u64));
            Some(self.cpu.now().saturating_add(ticks).max(1))
        } else {
            None
        };
        let guard = zone.lock(
            ZoneTables::bucket_of(mm, uaddr),
            &BoundedSpin(EL1_ZONE_LOCK_SPINS),
        )?;
        let Some(word) = self.user.read_u32(self.task, uaddr) else {
            drop(guard);
            return None;
        };
        if word != expected {
            drop(guard);
            frame.x[0] = EAGAIN as u64;
            return Some(Served::Returned { switched: false });
        }
        let fresh = zone.slot(slot).current().is_none();
        let affinity = zone.slot(slot).affinity();
        let record = zone
            .current_or_new(slot, identity_of(self.task, affinity))
            .ok()?;
        if deadline.is_some() && zone.slot(slot).host_record() != Some(record) {
            // Unreachable (checked above); never time a record the host
            // cannot take over.
            if fresh {
                zone.discard_unpublished(slot, record);
            }
            return None;
        }
        // SAFETY: this vCPU runs the thread `record` holds (a fresh home
        // record, or the switched-in `OnCpu` one); nobody else may touch it
        // until the park below is published.
        self.cpu
            .save(frame, unsafe { zone.record(record).ctx_mut() });
        let seq = zone.next_seq(record);
        if zone
            .enqueue(&guard, record, seq, mm, uaddr, bitset, 0)
            .is_err()
        {
            drop(guard);
            if fresh {
                zone.discard_unpublished(slot, record);
            }
            return None;
        }
        zone.set_deadline(record, deadline.unwrap_or(0));
        if deadline.is_some() {
            zone.arm_timer(slot, record, seq);
        }
        zone.publish_park(record, seq);
        drop(guard);
        zone.clear_current(slot);
        zone.counters.el1_parks.fetch_add(1, Ordering::Relaxed);
        Some(self.run_next(frame))
    }

    /// The running thread parked: run the next runnable thread, or idle.
    fn run_next(&mut self, frame: &mut TrapFrame) -> Served {
        if let Some(switched) = self.zone.switch_in_full(self.slot) {
            self.load(frame, switched);
            return Served::Returned { switched: true };
        }
        self.idle(frame)
    }

    /// Make the switched-in thread the running one.
    fn load(&mut self, frame: &mut TrapFrame, switched: SwitchedIn) {
        let (zone, slot) = (self.zone, self.slot);
        let rec = zone.record(switched.record);
        // SAFETY: switch_in_full made the record OnCpu on this slot.
        let ctx = unsafe { rec.ctx_mut() };
        self.cpu.load(frame, ctx);
        self.task.orig_arg0.store(ctx.x[0], Ordering::Relaxed);
        if let Some(result) = switched.result {
            frame.x[0] = result;
        }
        publish_identity(self.task, rec.identity());
        if zone.slot(slot).queued() != 0 {
            zone.slot(slot).restart_slice(self.cpu.now());
        }
        self.program_timer(true);
    }

    /// Nothing is runnable on this vCPU: poll, then park in WFI, until a
    /// thread is queued here (by another vCPU, or this vCPU's timer ending
    /// its timed park) or host work arrives.
    fn idle(&mut self, frame: &mut TrapFrame) -> Served {
        let (zone, slot) = (self.zone, self.slot);
        zone.counters
            .el1_idle_entries
            .fetch_add(1, Ordering::Relaxed);
        zone.slot(slot).set_sgi_target(self.cpu.own_sgi_target());
        zone.enter_idle(slot, false);
        let spin_until = self.cpu.now().saturating_add(self.ticks(IDLE_SPIN_NS));
        loop {
            self.take_irqs();
            if self.task.has_pending_host_work() {
                zone.leave_idle(slot);
                zone.counters.el1_idle_exits.fetch_add(1, Ordering::Relaxed);
                return Served::Idle;
            }
            let now = self.cpu.now();
            let _ = zone.expire_timer(slot, now);
            if let Some(switched) = zone.switch_in_full(slot) {
                zone.leave_idle(slot);
                self.load(frame, switched);
                return Served::Returned { switched: true };
            }
            if now < spin_until {
                self.cpu.spin();
                continue;
            }
            if zone.enter_idle(slot, true) {
                self.program_timer(false);
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
                    self.task.mark_pending_host_work();
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
    pub fn serve_irq(&mut self, frame: &mut TrapFrame) -> carrick_el1_abi::Action {
        self.take_irqs();
        if self.task.has_pending_host_work() {
            return carrick_el1_abi::Action::Forward;
        }
        if self.task.zone_mm.load(Ordering::Acquire) == 0 {
            return carrick_el1_abi::Action::Served;
        }
        let (zone, slot) = (self.zone, self.slot);
        let now = self.cpu.now();
        let _ = zone.expire_timer(slot, now);
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
                if zone.slot(slot).queued() != 0 {
                    self.preempt(frame);
                } else {
                    zone.slot(slot).restart_slice(now);
                }
            }
        }
        self.program_timer(true);
        carrick_el1_abi::Action::Served
    }

    /// Preempt the running thread: it goes to the tail of this vCPU's run
    /// queue with its registers, and the head runs.
    fn preempt(&mut self, frame: &mut TrapFrame) {
        let (zone, slot) = (self.zone, self.slot);
        if zone.runnable_head(slot).is_none() {
            return;
        }
        let fresh = zone.slot(slot).current().is_none();
        let affinity = zone.slot(slot).affinity();
        let Ok(prev) = zone.current_or_new(slot, identity_of(self.task, affinity)) else {
            return;
        };
        // SAFETY: `prev` holds the running thread (a fresh home record, or
        // the switched-in OnCpu one): this vCPU is its only owner.
        self.cpu.save(frame, unsafe { zone.record(prev).ctx_mut() });
        match zone.switch_in_full(slot) {
            Some(switched) => {
                zone.requeue_preempted(slot, prev);
                self.load(frame, switched);
            }
            None => {
                // The head changed under us (it cannot: only this vCPU takes
                // from its queue). Keep running `prev`.
                if fresh {
                    zone.discard_unpublished(slot, prev);
                }
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
        for target in &effects.sgi[..effects.sgis] {
            self.cpu
                .send_sgi(*target | (u64::from(GIC_RESCHED_INTID) << 24));
            self.zone.counters.el1_sgis.fetch_add(1, Ordering::Relaxed);
        }
    }
}

mod hw;
#[cfg(target_os = "none")]
pub use hw::HardwareCpu;
pub use hw::HardwareUserWord;

/// The live system and FP/SIMD registers a switch moves, as plain fields.
#[cfg(test)]
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
#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FakeCpu {
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
    pub mpidr: u64,
    /// Negative control: a switch that forgets FP/SIMD.
    pub skip_fpsimd: bool,
}

#[cfg(test)]
impl Default for FakeCpu {
    fn default() -> Self {
        Self {
            regs: FakeRegs::default(),
            now: 1_000_000,
            freq: 24_000_000,
            spin_ticks: 24,
            timer: None,
            pending: std::collections::VecDeque::new(),
            sgis: std::vec::Vec::new(),
            wfis: 0,
            mpidr: 0x8000_0003,
            skip_fpsimd: false,
        }
    }
}

#[cfg(test)]
impl ThreadCpu for FakeCpu {
    fn save(&mut self, frame: &TrapFrame, ctx: &mut ThreadCtx) {
        ctx.x = frame.x;
        ctx.pc = frame.elr;
        ctx.pstate = frame.spsr;
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

    fn load(&mut self, frame: &mut TrapFrame, ctx: &ThreadCtx) {
        frame.x = ctx.x;
        frame.elr = ctx.pc;
        frame.spsr = ctx.pstate;
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

#[cfg(test)]
mod tests;
