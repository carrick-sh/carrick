//! Native scheduler transport for the Linux-owned futex client.
pub use crate::substrate::sched::*;
use carrick_el1_abi::TrapFrame;
use carrick_el1_abi::{ReservationMm, UserVa};
use carrick_guest_arch::CounterTick;
pub use carrick_personality_linux::sched::{
    EAGAIN, ETIMEDOUT_RESULT, FUTEX_WAIT_BITSET_PRIVATE, FUTEX_WAIT_PRIVATE,
    FUTEX_WAKE_BITSET_PRIVATE, FUTEX_WAKE_PRIVATE, SYS_FUTEX,
};
use carrick_personality_linux::sched::{FutexCall, FutexFrequency, FutexVenue, FutexWait};
use core::sync::atomic::Ordering;

pub fn is_served_futex_op(frame: &TrapFrame) -> bool {
    ::carrick_personality_linux::sched::is_served_futex_op(
        frame.x[8],
        crate::personality::sched::args(frame),
    )
}
fn args(frame: &TrapFrame) -> [u64; 6] {
    [
        frame.x[0], frame.x[1], frame.x[2], frame.x[3], frame.x[4], frame.x[5],
    ]
}
struct Adapter<'a, 's, C: ThreadCpu, U: UserWord> {
    sched: &'a mut Sched<'s, C, U>,
    frame: &'a mut TrapFrame,
}
impl<C: ThreadCpu, U: UserWord> FutexVenue for Adapter<'_, '_, C, U> {
    type Served = Served;
    fn mm(&self) -> Option<ReservationMm> {
        ReservationMm::new(self.sched.task.mm.key.load(Ordering::Acquire))
    }
    fn timed_wait_allowed(&self) -> bool {
        let slot = self.sched.zone.slot(self.sched.slot);
        slot.current().is_none() || slot.current() == slot.host_record()
    }
    fn read_u64(&self, address: UserVa) -> Option<u64> {
        self.sched.user.read_u64(self.sched.task, address.raw())
    }
    fn frequency(&self) -> FutexFrequency {
        FutexFrequency::from_hz(self.sched.cpu.freq())
    }
    fn now(&self) -> CounterTick {
        CounterTick::new(self.sched.cpu.now())
    }
    fn wake(
        &mut self,
        mm: ReservationMm,
        address: UserVa,
        bitset: u32,
        limit: u32,
    ) -> Option<Served> {
        self.sched
            .wake_word(self.frame, mm.raw(), address.raw(), bitset, limit)
    }
    fn wait(&mut self, wait: FutexWait) -> Option<Served> {
        self.sched.wait_word(
            self.frame,
            wait.mm.raw(),
            wait.address.raw(),
            wait.bitset,
            wait.expected,
            wait.deadline.map(CounterTick::raw),
            wait.mismatch_result.raw() as u64,
            wait.timeout_result.raw() as u64,
        )
    }
}
impl<C: ThreadCpu, U: UserWord> Sched<'_, C, U> {
    pub fn serve_futex(&mut self, frame: &mut TrapFrame) -> Option<Served> {
        if !is_served_futex_op(frame) {
            return None;
        }
        let call = FutexCall {
            args: crate::personality::sched::args(frame),
        };
        ::carrick_personality_linux::sched::serve_futex(call, &mut Adapter { sched: self, frame })
    }
    pub fn serve_irq(&mut self, frame: &mut TrapFrame) -> carrick_el1_abi::Action {
        self.interrupt(frame, ETIMEDOUT_RESULT)
    }
    pub fn serve_idle_entry(&mut self, frame: &mut TrapFrame) -> carrick_el1_abi::Action {
        self.idle_entry(frame, ETIMEDOUT_RESULT)
    }
}
