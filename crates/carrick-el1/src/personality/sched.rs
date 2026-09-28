//! Linux futex decoding and completion values for EL1 scheduling.
pub use crate::substrate::sched::*;
use carrick_el1_abi::TrapFrame;
use core::sync::atomic::Ordering;
pub const SYS_FUTEX: usize = 98;
pub(crate) const FUTEX_WAIT_PRIVATE: u64 = 128;
pub(crate) const FUTEX_WAKE_PRIVATE: u64 = 129;
pub(crate) const FUTEX_WAIT_BITSET_PRIVATE: u64 = 128 | 9;
pub(crate) const FUTEX_WAKE_BITSET_PRIVATE: u64 = 128 | 10;
pub(crate) const EAGAIN: i64 = -11;
pub(crate) const ETIMEDOUT_RESULT: u64 = (-110_i64) as u64;

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

impl<C: ThreadCpu, U: UserWord> Sched<'_, C, U> {
    /// Serve a futex syscall at EL1, or `None` to forward it unchanged.
    pub fn serve_futex(&mut self, frame: &mut TrapFrame) -> Option<Served> {
        let mm = self.task.zone_mm.load(Ordering::Acquire);
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
                self.wake_word(frame, mm, uaddr, bitset, frame.x[2] as i32 as u32)
            }
            FUTEX_WAIT_PRIVATE | FUTEX_WAIT_BITSET_PRIVATE => self.serve_wait(frame, mm, uaddr),
            _ => None,
        }
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
        self.wait_word(
            frame,
            mm,
            uaddr,
            bitset,
            expected,
            deadline,
            EAGAIN as u64,
            ETIMEDOUT_RESULT,
        )
    }
    pub fn serve_irq(&mut self, frame: &mut TrapFrame) -> carrick_el1_abi::Action {
        self.interrupt(frame, ETIMEDOUT_RESULT)
    }
    pub fn serve_idle_entry(&mut self, frame: &mut TrapFrame) -> carrick_el1_abi::Action {
        self.idle_entry(frame, ETIMEDOUT_RESULT)
    }
}
