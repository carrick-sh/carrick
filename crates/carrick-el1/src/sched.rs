//! In-guest futex handoff (EL1 plan 1b).
//!
//! EL1 serves `FUTEX_WAKE(_BITSET)_PRIVATE` and untimed
//! `FUTEX_WAIT(_BITSET)_PRIVATE` for a zone process, on the zone tables it
//! shares with the host (`carrick_sched_core`):
//!
//! - a wake claims parked waiters of the same process onto this vCPU slot's
//!   run queue (it never runs them itself);
//! - a wait parks the running thread and switches the vCPU to the oldest
//!   woken thread on the run queue: register state, `SP_EL0`, the thread
//!   pointers, `CONTEXTIDR_EL1` and FP/SIMD are saved to the parked record
//!   and loaded from the woken one, with no host exit;
//! - a wait with nothing to switch to is forwarded (the host parks the
//!   thread in the same queues), and so is every other case: timeouts,
//!   requeue, `futex_waitv`, shared futexes, a busy bucket, a full run queue,
//!   a fault on the futex word.
//!
//! While woken threads wait on the run queue, any syscall other than a
//! served futex operation is forwarded, so the host takes them at that exit.

use carrick_el1_abi::{
    CurrentTask, RecordId, SlotId, ThreadCtx, ThreadIdentity, TrapFrame, Waker, ZoneTables,
};
use carrick_sched_core::{BoundedSpin, ZONE_RUNQ_CAPACITY};
use core::sync::atomic::Ordering;

pub const SYS_FUTEX: usize = 98;
const FUTEX_WAIT_PRIVATE: u64 = 128;
const FUTEX_WAKE_PRIVATE: u64 = 129;
const FUTEX_WAIT_BITSET_PRIVATE: u64 = 128 | 9;
const FUTEX_WAKE_BITSET_PRIVATE: u64 = 128 | 10;
const EAGAIN: i64 = -11;

/// Bucket-lock spins before EL1 gives up and forwards.
const EL1_ZONE_LOCK_SPINS: u32 = 1024;

/// Whether `frame` is a futex operation EL1 may serve (the rest forward).
pub fn is_served_futex_op(frame: &TrapFrame) -> bool {
    if frame.x[8] as usize != SYS_FUTEX || frame.x[0] & 3 != 0 {
        return false;
    }
    match frame.x[1] {
        FUTEX_WAIT_PRIVATE => frame.x[3] == 0,
        FUTEX_WAIT_BITSET_PRIVATE => frame.x[3] == 0 && frame.x[5] as u32 != 0,
        FUTEX_WAKE_PRIVATE => (frame.x[2] as i32) > 0,
        FUTEX_WAKE_BITSET_PRIVATE => (frame.x[2] as i32) > 0 && frame.x[5] as u32 != 0,
        _ => false,
    }
}

/// The CPU state an in-guest switch moves besides the trap frame.
pub trait ThreadCpu {
    /// Save the running thread's `frame` and live state into `ctx`.
    fn save(&mut self, frame: &TrapFrame, ctx: &mut ThreadCtx);
    /// Make `ctx` the running thread: fill `frame` and load live state.
    fn load(&mut self, frame: &mut TrapFrame, ctx: &ThreadCtx);
    /// The virtual counter (for the host's run-queue guard).
    fn now(&self) -> u64;
}

/// Reads the futex word from guest user memory.
pub trait UserWord {
    /// The 32-bit word at `uaddr`, or `None` if EL0 cannot read it.
    fn read_u32(&self, task: &CurrentTask, uaddr: u64) -> Option<u32>;
}

/// The running thread's identity, as the host published it (for the
/// host-loaded thread) or EL1 did after a switch.
fn identity_of(task: &CurrentTask) -> ThreadIdentity {
    ThreadIdentity {
        tid: task.task_id.load(Ordering::Relaxed),
        serial: task.thread_serial.load(Ordering::Relaxed),
        mm: task.zone_mm.load(Ordering::Relaxed),
        file_table: task.file_table.load(Ordering::Relaxed),
        generation: task.generation.load(Ordering::Relaxed),
    }
}

/// Publish the switched-in thread as the slot's running task.
fn publish_identity(task: &CurrentTask, id: ThreadIdentity) {
    task.task_id.store(id.tid, Ordering::Relaxed);
    task.thread_serial.store(id.serial, Ordering::Relaxed);
    task.file_table.store(id.file_table, Ordering::Relaxed);
    task.generation.store(id.generation, Ordering::Release);
}

/// A futex syscall EL1 served.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Served {
    /// The caller parked and the vCPU now runs another thread: the frame and
    /// the slot's task record are that thread's.
    pub switched: bool,
}

/// Serve a futex syscall at EL1, or `None` to forward it unchanged.
pub fn serve_futex(
    frame: &mut TrapFrame,
    slot: SlotId,
    task: &CurrentTask,
    zone: &ZoneTables,
    cpu: &mut impl ThreadCpu,
    user: &impl UserWord,
) -> Option<Served> {
    let mm = task.zone_mm.load(Ordering::Acquire);
    if mm == 0 || !is_served_futex_op(frame) {
        return None;
    }
    let uaddr = frame.x[0];
    match frame.x[1] {
        FUTEX_WAKE_PRIVATE | FUTEX_WAKE_BITSET_PRIVATE => {
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
            let n = zone
                .wake(
                    &guard,
                    mm,
                    uaddr,
                    bitset,
                    count,
                    Waker::El1 { slot },
                    &mut woken,
                )
                .ok()?;
            drop(guard);
            if n > 0 && was_empty {
                zone.note_queued_since(slot, cpu.now());
            }
            frame.x[0] = u64::from(n);
            Some(Served { switched: false })
        }
        FUTEX_WAIT_PRIVATE | FUTEX_WAIT_BITSET_PRIVATE => {
            let bitset = if frame.x[1] == FUTEX_WAIT_PRIVATE {
                u32::MAX
            } else {
                frame.x[5] as u32
            };
            let expected = frame.x[2] as u32;
            // Park only with a woken thread to switch to; otherwise the host
            // parks this one in the same queues (one exit, the vCPU idles).
            let next = peek_runnable(zone, slot)?;
            let guard = zone.lock(
                ZoneTables::bucket_of(mm, uaddr),
                &BoundedSpin(EL1_ZONE_LOCK_SPINS),
            )?;
            let Some(word) = user.read_u32(task, uaddr) else {
                drop(guard);
                return None;
            };
            if word != expected {
                drop(guard);
                frame.x[0] = EAGAIN as u64;
                return Some(Served { switched: false });
            }
            let fresh = zone.slot(slot).current().is_none();
            let record = zone.current_or_new(slot, identity_of(task)).ok()?;
            // SAFETY: this vCPU runs the thread `record` holds (a fresh
            // record, or the switched-in `OnCpu` one); nobody else may touch
            // it until the park below is published.
            cpu.save(frame, unsafe { zone.record(record).ctx_mut() });
            let seq = zone.next_seq(record);
            if zone
                .enqueue(&guard, record, seq, mm, uaddr, bitset, 0)
                .is_err()
            {
                drop(guard);
                if fresh {
                    zone.free_record(record);
                }
                return None;
            }
            zone.publish_park(record, seq);
            drop(guard);
            zone.clear_current(slot);
            zone.counters.el1_parks.fetch_add(1, Ordering::Relaxed);
            let switched = zone.switch_in(slot);
            if switched != Some(next) {
                // `next` was validated on this slot's own run queue, which
                // only this vCPU changes while it runs: unreachable.
                panic!("EL1 zone switch lost its validated successor");
            }
            let rec = zone.record(next);
            // SAFETY: switch_in made `next` OnCpu on this slot.
            let ctx = unsafe { rec.ctx_mut() };
            cpu.load(frame, ctx);
            task.orig_arg0.store(ctx.x[0], Ordering::Relaxed);
            frame.x[0] = rec.result();
            publish_identity(task, rec.identity());
            Some(Served { switched: true })
        }
        _ => None,
    }
}

/// The oldest woken thread on `slot`'s run queue, if it can be switched to.
fn peek_runnable(zone: &ZoneTables, slot: SlotId) -> Option<RecordId> {
    zone.runnable_head(slot)
}

mod hw;
#[cfg(target_os = "none")]
pub use hw::HardwareCpu;
pub use hw::HardwareUserWord;

/// A host-test stand-in for the CPU: the live system and FP/SIMD registers
/// as plain fields, so a switch's save and load can be checked exactly.
#[cfg(test)]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FakeCpu {
    pub sp_el0: u64,
    pub tpidr_el0: u64,
    pub tpidrro_el0: u64,
    pub contextidr_el1: u64,
    pub v: [u128; 32],
    pub fpsr: u64,
    pub fpcr: u64,
    pub now: u64,
    /// Negative control: a switch that forgets FP/SIMD.
    pub skip_fpsimd: bool,
}

#[cfg(test)]
impl ThreadCpu for FakeCpu {
    fn save(&mut self, frame: &TrapFrame, ctx: &mut ThreadCtx) {
        ctx.x = frame.x;
        ctx.pc = frame.elr;
        ctx.pstate = frame.spsr;
        ctx.sp_el0 = self.sp_el0;
        ctx.tpidr_el0 = self.tpidr_el0;
        ctx.tpidrro_el0 = self.tpidrro_el0;
        ctx.contextidr_el1 = self.contextidr_el1;
        if !self.skip_fpsimd {
            ctx.v = self.v;
            ctx.fpsr = self.fpsr;
            ctx.fpcr = self.fpcr;
        }
    }

    fn load(&mut self, frame: &mut TrapFrame, ctx: &ThreadCtx) {
        frame.x = ctx.x;
        frame.elr = ctx.pc;
        frame.spsr = ctx.pstate;
        self.sp_el0 = ctx.sp_el0;
        self.tpidr_el0 = ctx.tpidr_el0;
        self.tpidrro_el0 = ctx.tpidrro_el0;
        self.contextidr_el1 = ctx.contextidr_el1;
        if !self.skip_fpsimd {
            self.v = ctx.v;
            self.fpsr = ctx.fpsr;
            self.fpcr = ctx.fpcr;
        }
    }

    fn now(&self) -> u64 {
        self.now
    }
}

#[cfg(test)]
mod tests;
