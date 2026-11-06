//! Native scheduler transport for the Linux-owned futex client.
pub use carrick_el1::substrate::sched::*;
use carrick_el1_abi::TrapFrame;
use carrick_el1_abi::{ReservationMm, UserVa};
use carrick_guest_arch::CounterTick;
use carrick_guest_arch::ProcessContext;
pub use carrick_personality_linux::sched::{
    EAGAIN, ETIMEDOUT_RESULT, FUTEX_WAIT_BITSET_PRIVATE, FUTEX_WAIT_PRIVATE,
    FUTEX_WAKE_BITSET_PRIVATE, FUTEX_WAKE_PRIVATE, SYS_FUTEX,
};
use carrick_personality_linux::sched::{FutexCall, FutexFrequency, FutexVenue, FutexWait};
use core::sync::atomic::Ordering;

/// ARM's Linux execution entry: the substrate moves registers, then this
/// adapter re-enters the admitted native process owner before EL0 resumes.
#[cfg(all(target_os = "none", target_arch = "aarch64"))]
pub struct HardwareCpu;

#[cfg(all(target_os = "none", target_arch = "aarch64"))]
impl ThreadCpu for HardwareCpu {
    fn save(&mut self, frame: &TrapFrame, ctx: &mut carrick_el1_abi::Aarch64ParkedContext) {
        carrick_el1::substrate::sched::hw::HardwareCpu.save(frame, ctx);
    }
    fn load(&mut self, frame: &mut TrapFrame, ctx: &carrick_el1_abi::Aarch64ParkedContext) {
        carrick_el1::substrate::sched::hw::HardwareCpu.load(frame, ctx);
    }
    fn resume_lifecycle(
        &mut self,
        zone: &carrick_el1_abi::ZoneTables,
        task: &carrick_el1_abi::CurrentTask,
        slot: carrick_el1_abi::SlotId,
        record: carrick_el1_abi::RecordId,
    ) -> ResumeAction {
        // SAFETY: these references point into fixed image-lifetime EL1 ABI
        // storage, and the scheduler owns this slot through the checkpoint.
        let zone = unsafe { &*(zone as *const carrick_el1_abi::ZoneTables) };
        let task = unsafe { &*(task as *const carrick_el1_abi::CurrentTask) };
        super::aarch64_process::resume_production(zone, task, slot, record)
    }
    fn host_work_boundary(
        &mut self,
        _: &carrick_el1_abi::ZoneTables,
        task: &carrick_el1_abi::CurrentTask,
        _: carrick_el1_abi::SlotId,
        _: carrick_el1_abi::RecordId,
        frame: &mut TrapFrame,
        counters: &carrick_el1_abi::Counters,
    ) -> carrick_el1_abi::Action {
        let action = if task.linux.served_boundary_pending() {
            carrick_el1_abi::Action::ServedWithWork
        } else {
            carrick_el1_abi::Action::Forward
        };
        super::dispatch::capture_native_service_exit(frame, action, None, counters)
    }
    fn set_translation(&mut self, a: u64, b: u64) {
        carrick_el1::substrate::sched::hw::HardwareCpu.set_translation(a, b);
    }
    fn invalidate_asid(&mut self, root: u64) {
        carrick_el1::substrate::sched::hw::HardwareCpu.invalidate_asid(root);
    }
    fn live_ttbr0(&self) -> Option<u64> {
        carrick_el1::substrate::sched::hw::HardwareCpu.live_ttbr0()
    }
    fn now(&self) -> u64 {
        carrick_el1::substrate::sched::hw::HardwareCpu.now()
    }
    fn freq(&self) -> u64 {
        carrick_el1::substrate::sched::hw::HardwareCpu.freq()
    }
    fn set_timer(&mut self, deadline: Option<u64>) {
        carrick_el1::substrate::sched::hw::HardwareCpu.set_timer(deadline);
    }
    fn send_sgi(&mut self, route: u64) {
        carrick_el1::substrate::sched::hw::HardwareCpu.send_sgi(route);
    }
    fn ack_irq(&mut self) -> u32 {
        carrick_el1::substrate::sched::hw::HardwareCpu.ack_irq()
    }
    fn end_irq(&mut self, intid: u32) {
        carrick_el1::substrate::sched::hw::HardwareCpu.end_irq(intid);
    }
    fn wait_for_interrupt(&mut self) {
        carrick_el1::substrate::sched::hw::HardwareCpu.wait_for_interrupt();
    }
    fn spin(&mut self) {
        carrick_el1::substrate::sched::hw::HardwareCpu.spin();
    }
    fn own_sgi_target(&self) -> u64 {
        carrick_el1::substrate::sched::hw::HardwareCpu.own_sgi_target()
    }
}

pub fn is_served_futex_op(frame: &TrapFrame) -> bool {
    ::carrick_personality_linux::sched::is_served_futex_op(frame.x[8], crate::sched::args(frame))
}
fn args(frame: &TrapFrame) -> [u64; 6] {
    [
        frame.x[0], frame.x[1], frame.x[2], frame.x[3], frame.x[4], frame.x[5],
    ]
}
struct Adapter<'a, 's, C: ThreadCpu, U: UserWord> {
    sched: &'a mut Sched<'s, C, U>,
    frame: &'a mut TrapFrame,
    refusal: Option<carrick_core::personality::CopyOutcome>,
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
    fn relative_deadline(&mut self, _key: u64, proposed: CounterTick) -> CounterTick {
        if let Some(deadline) = core::num::NonZeroU64::new(self.frame.far) {
            return CounterTick::new(deadline.get());
        }
        let record = self
            .sched
            .zone
            .slot(self.sched.slot)
            .current()
            .or_else(|| self.sched.zone.slot(self.sched.slot).host_record());
        let deadline = record.and_then(|record| {
            // SAFETY: the executing slot owns this current/host record.
            unsafe {
                self.sched
                    .zone
                    .record(record)
                    .ctx_mut()
                    .relative_futex_deadline()
            }
        });
        if let Some(deadline) = deadline {
            self.frame.far = deadline;
            return CounterTick::new(deadline);
        }
        self.frame.far = proposed.raw();
        proposed
    }
    fn finish_relative_wait(&mut self) {
        if let Some(record) = self
            .sched
            .zone
            .slot(self.sched.slot)
            .current()
            .or_else(|| self.sched.zone.slot(self.sched.slot).host_record())
        {
            // SAFETY: the executing slot owns this current/host record.
            unsafe {
                self.sched
                    .zone
                    .record(record)
                    .ctx_mut()
                    .clear_relative_futex_deadline();
            }
        }
        self.frame.far = 0;
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
        let zone = self.sched.zone;
        let result = self.sched.wait_word_with(
            self.frame,
            wait.mm.raw(),
            wait.address.raw(),
            wait.bitset,
            wait.expected,
            wait.deadline.map(CounterTick::raw),
            wait.mismatch_result.raw() as u64,
            wait.timeout_result.raw() as u64,
            |record| {
                crate::aarch64_process::registry()
                    .futex_signal_pending(zone, record)
                    .then_some(carrick_guest_arch::NativeReturnWord(
                        carrick_syscall_abi::LINUX_EINTR.guest_retval() as u64,
                    ))
            },
            |user, task, address| {
                use carrick_core::personality::{CopyOutcome, UserCopy};
                let mut copy = FutexCopy { task, user };
                let mut word = 0;
                match copy.atomic_load_u32(UserVa::new(address), &mut word) {
                    CopyOutcome::Done => Ok(word),
                    refusal => Err(refusal),
                }
            },
        );
        match result {
            Ok(served) => served,
            Err(refusal) => {
                self.refusal = Some(refusal);
                None
            }
        }
    }
}

/// Adapt the scheduler's ISA word reader to the one typed copy interface.
/// Test venues can withhold backing without dereferencing an absent host page.
struct FutexCopy<'a, U> {
    task: &'a carrick_el1_abi::CurrentTask,
    user: &'a U,
}
impl<U: UserWord> carrick_core::personality::UserCopy for FutexCopy<'_, U> {
    fn copy_in(&mut self, dst: &mut [u8], src: UserVa) -> carrick_core::personality::CopyOutcome {
        carrick_core::personality::UserCopy::copy_in(
            &mut crate::file::ValidatedCopy {
                task: self.task,
                validator: &crate::file::HardwareValidator,
            },
            dst,
            src,
        )
    }
    fn copy_out(&mut self, dst: UserVa, src: &[u8]) -> carrick_core::personality::CopyOutcome {
        carrick_core::personality::UserCopy::copy_out(
            &mut crate::file::ValidatedCopy {
                task: self.task,
                validator: &crate::file::HardwareValidator,
            },
            dst,
            src,
        )
    }
    fn atomic_load_u32(
        &mut self,
        address: UserVa,
        value: &mut u32,
    ) -> carrick_core::personality::CopyOutcome {
        use carrick_core::personality::{CopyOutcome, atomic_word_refusal};
        let refusal = atomic_word_refusal(address, carrick_guest_arch::Access::Read);
        if refusal == CopyOutcome::Fault {
            return refusal;
        }
        match self.user.read_u32(self.task, address.raw()) {
            Some(word) => {
                #[cfg(all(target_os = "none", target_arch = "aarch64"))]
                // SAFETY: acquire ordering after the guarded unprivileged load.
                unsafe {
                    core::arch::asm!("dmb ishld", options(nostack, preserves_flags));
                }
                *value = word;
                CopyOutcome::Done
            }
            None => refusal,
        }
    }
}
/// Linux entry points over the neutral scheduler: futex service and the
/// timer-expiry result its interrupt and idle paths report.
pub trait LinuxSchedEntry {
    fn serve_futex(&mut self, frame: &mut TrapFrame) -> Option<Served>;
    fn serve_futex_typed(
        &mut self,
        frame: &mut TrapFrame,
    ) -> Result<Option<Served>, carrick_core::personality::CopyOutcome>;
    fn serve_irq(&mut self, frame: &mut TrapFrame) -> carrick_el1_abi::Action;
    fn serve_idle_entry(&mut self, frame: &mut TrapFrame) -> carrick_el1_abi::Action;
}
impl<C: ThreadCpu, U: UserWord> LinuxSchedEntry for Sched<'_, C, U> {
    fn serve_futex(&mut self, frame: &mut TrapFrame) -> Option<Served> {
        self.serve_futex_typed(frame).ok().flatten()
    }
    fn serve_futex_typed(
        &mut self,
        frame: &mut TrapFrame,
    ) -> Result<Option<Served>, carrick_core::personality::CopyOutcome> {
        if !is_served_futex_op(frame) {
            return Ok(None);
        }
        let call = FutexCall {
            args: crate::sched::args(frame),
        };
        let mut adapter = Adapter {
            sched: self,
            frame,
            refusal: None,
        };
        let served = ::carrick_personality_linux::sched::serve_futex(call, &mut adapter);
        match adapter.refusal {
            Some(refusal) => Err(refusal),
            None => Ok(served),
        }
    }
    fn serve_irq(&mut self, frame: &mut TrapFrame) -> carrick_el1_abi::Action {
        self.interrupt(frame, ETIMEDOUT_RESULT)
    }
    fn serve_idle_entry(&mut self, frame: &mut TrapFrame) -> carrick_el1_abi::Action {
        self.idle_entry(frame, ETIMEDOUT_RESULT)
    }
}

#[cfg(test)]
mod tests;
