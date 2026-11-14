//! Native scheduler transport for the Linux-owned futex client.
pub use carrick_el1::substrate::sched::*;
use carrick_el1_abi::TrapFrame;
use carrick_el1_abi::{ReservationMm, UserVa};
use carrick_guest_arch::CounterTick;
use carrick_personality_linux::lifecycle::LifecycleOutcome;
pub use carrick_personality_linux::sched::{
    EAGAIN, ETIMEDOUT_RESULT, FUTEX_WAIT_BITSET_PRIVATE, FUTEX_WAIT_PRIVATE,
    FUTEX_WAKE_BITSET_PRIVATE, FUTEX_WAKE_PRIVATE, SYS_FUTEX,
};
use carrick_personality_linux::sched::{
    FutexCall, FutexFrequency, FutexVenue, FutexWait, MmFutexKey, RelativeFutexWait,
};
use core::sync::atomic::Ordering;

/// ARM's Linux execution entry: the substrate moves registers, then this
/// adapter re-enters the admitted native process owner before EL0 resumes.
#[cfg(all(target_os = "none", target_arch = "aarch64"))]
pub struct HardwareCpu;

#[cfg(all(target_os = "none", target_arch = "aarch64"))]
impl ThreadCpu for HardwareCpu {
    fn save(
        &mut self,
        frame: &TrapFrame,
        ctx: &mut carrick_el1_abi::Aarch64ParkedContext,
        exit: CpuExitCause,
    ) {
        carrick_el1::substrate::sched::hw::HardwareCpu.save(frame, ctx, exit);
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
/// The admitted process's shared-private authority: whether a shared futex
/// word is private anonymous storage of its MM
/// ([`carrick_personality_linux::lifecycle::ProcessNative::futex_shared_private`]).
/// `Err` is the memory owner's retry or failure outcome.
pub type SharedFutexMapping<'m> =
    dyn FnMut(UserVa, Option<RelativeFutexWait>) -> Result<bool, LifecycleOutcome> + 'm;

/// Why an admitted futex left the scheduler without a completion.
pub enum FutexRefusal {
    /// The word is not yet readable, or faults.
    Copy(carrick_core::user_copy::CopyOutcome),
    /// The shared word's memory owner retries or fails the syscall.
    Mapping(LifecycleOutcome),
}

struct Adapter<'a, 's, 'm, C: ThreadCpu, U: UserWord> {
    sched: &'a mut Sched<'s, C, U>,
    frame: &'a mut TrapFrame,
    refusal: Option<FutexRefusal>,
    operation: &'a mut Option<carrick_personality_linux::sched::RelativeFutexWait>,
    /// A shared candidate keys shared-private.
    shared: bool,
    /// A shared wait's mapping authority, run once policy decoded its
    /// relative expiry. A shared wake was authenticated before policy.
    authenticate: Option<&'a mut SharedFutexMapping<'m>>,
}
impl<C: ThreadCpu, U: UserWord> Adapter<'_, '_, '_, C, U> {
    /// The scheduler key of `address`: the shared-private key for an
    /// authenticated shared word, the private key otherwise. `None` leaves
    /// the call unserved (a mapping the authority refuses, or its retry).
    fn key(&mut self, address: UserVa) -> Option<u64> {
        if !self.shared {
            return MmFutexKey::private(address).map(MmFutexKey::scheduler_address);
        }
        if let Some(authenticate) = self.authenticate.as_deref_mut() {
            let retained = self.operation.as_ref().map(|wait| RelativeFutexWait {
                deadline: wait.deadline,
            });
            match authenticate(address, retained) {
                Ok(true) => {}
                Ok(false) => return None,
                Err(outcome) => {
                    self.refusal = Some(FutexRefusal::Mapping(outcome));
                    return None;
                }
            }
        }
        MmFutexKey::shared_private(address).map(MmFutexKey::scheduler_address)
    }
}
impl<C: ThreadCpu, U: UserWord> FutexVenue for Adapter<'_, '_, '_, C, U> {
    type Served = Served;
    fn mm(&self) -> Option<ReservationMm> {
        ReservationMm::new(self.sched.task.mm.key.load(Ordering::Acquire))
    }
    fn timed_wait_allowed(&self) -> bool {
        // Timers are leased to the exact record/park sequence, not to the
        // vCPU's host record. Native fork/exec descendants use that same
        // scheduler owner and must not escape to a nonexistent host task.
        true
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
    fn retained_deadline(&self) -> Option<CounterTick> {
        self.operation.as_ref().map(|op| op.deadline)
    }
    fn invalid(
        &mut self,
        result: carrick_personality_linux::entry::SyscallResult,
    ) -> Option<Served> {
        self.frame.x[0] = result.raw() as u64;
        Some(Served::Returned { switched: false })
    }
    fn wake(&mut self, mm: ReservationMm, address: UserVa, bitset: u32, limit: u32) -> Served {
        let Some(key) = (if self.shared {
            MmFutexKey::shared_private(address)
        } else {
            MmFutexKey::private(address)
        }) else {
            self.frame.x[0] = carrick_syscall_abi::LINUX_EINVAL.guest_retval() as u64;
            return Served::Returned { switched: false };
        };
        let key = key.scheduler_address();
        self.sched
            .wake_word(self.frame, mm.raw(), key, bitset, limit)
    }
    fn wait(&mut self, wait: FutexWait) -> Option<Served> {
        if self.operation.is_none()
            && let Some(deadline) = wait.deadline
        {
            *self.operation =
                Some(carrick_personality_linux::sched::RelativeFutexWait { deadline });
        }
        // Policy decoded the relative expiry first: a mapping retry retains it.
        let key = self.key(wait.address)?;

        let zone = self.sched.zone;
        let binding = carrick_core::entry::binding(&self.sched.task.execution, &self.sched.task.mm);
        let result = self.sched.wait_word_with(
            self.frame,
            wait.mm.raw(),
            key,
            wait.bitset,
            wait.expected,
            wait.deadline.map(CounterTick::raw),
            wait.mismatch_result.raw() as u64,
            wait.timeout_result.raw() as u64,
            |record| {
                crate::aarch64_process::registry()
                    .futex_interrupt_pending(zone, record, binding)
                    .then_some(carrick_guest_arch::NativeReturnWord(
                        carrick_syscall_abi::LINUX_EINTR.guest_retval() as u64,
                    ))
            },
            // The key may carry the shared-private tag; the word is read at
            // the guest's own address.
            |user, task, _key| {
                use carrick_core::user_copy::{CopyOutcome, UserCopy};
                let mut copy = FutexCopy { task, user };
                let mut word = 0;
                match copy.atomic_load_u32(wait.address, &mut word) {
                    CopyOutcome::Done => Ok(word),
                    refusal => Err(refusal),
                }
            },
        );
        match result {
            Ok(served) => served,
            Err(refusal) => {
                self.refusal = Some(FutexRefusal::Copy(refusal));
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

fn futex_word_refusal(address: UserVa) -> carrick_core::user_copy::CopyOutcome {
    #[cfg(target_os = "none")]
    {
        carrick_core::user_copy::atomic_word_refusal(address, carrick_guest_arch::Access::Read)
    }
    #[cfg(not(target_os = "none"))]
    {
        use carrick_core::user_copy::{CopyOutcome, GuestCopyRequest};
        if address.raw() & 3 != 0 {
            CopyOutcome::Fault
        } else {
            CopyOutcome::NotYet(GuestCopyRequest {
                address,
                len: carrick_guest_arch::GuestLen::new(4),
                access: carrick_guest_arch::Access::Read,
            })
        }
    }
}

impl<U: UserWord> carrick_core::user_copy::UserCopy for FutexCopy<'_, U> {
    fn copy_in(&mut self, dst: &mut [u8], src: UserVa) -> carrick_core::user_copy::CopyOutcome {
        carrick_core::user_copy::UserCopy::copy_in(
            &mut crate::file::ValidatedCopy {
                task: self.task,
                validator: &crate::file::HardwareValidator,
            },
            dst,
            src,
        )
    }
    fn copy_out(&mut self, dst: UserVa, src: &[u8]) -> carrick_core::user_copy::CopyOutcome {
        carrick_core::user_copy::UserCopy::copy_out(
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
    ) -> carrick_core::user_copy::CopyOutcome {
        use carrick_core::user_copy::CopyOutcome;
        let refusal = futex_word_refusal(address);
        if refusal == CopyOutcome::Fault {
            return refusal;
        }
        match self.user.read_u32(self.task, address.raw()) {
            Some(word) => {
                // Acquire ordering after the guarded unprivileged load; lowers to
                // `dmb ishld` on aarch64 without unreviewed inline assembly.
                core::sync::atomic::fence(core::sync::atomic::Ordering::Acquire);
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
    ) -> Result<Option<Served>, carrick_core::user_copy::CopyOutcome>;
    /// Serve an admitted futex. With `shared`, a shared spelling of an
    /// admitted PRIVATE op is a candidate too, keyed shared-private once
    /// `shared` authenticates its word (#2124).
    fn serve_futex_operation(
        &mut self,
        frame: &mut TrapFrame,
        operation: &mut Option<carrick_personality_linux::sched::RelativeFutexWait>,
        shared: Option<&mut SharedFutexMapping<'_>>,
    ) -> Result<Option<Served>, FutexRefusal>;
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
    ) -> Result<Option<Served>, carrick_core::user_copy::CopyOutcome> {
        // No mapping authority: no shared candidate, so no mapping refusal.
        match self.serve_futex_operation(frame, &mut None, None) {
            Ok(served) => Ok(served),
            Err(FutexRefusal::Copy(refusal)) => Err(refusal),
            Err(FutexRefusal::Mapping(_)) => Ok(None),
        }
    }
    fn serve_futex_operation(
        &mut self,
        frame: &mut TrapFrame,
        operation: &mut Option<carrick_personality_linux::sched::RelativeFutexWait>,
        shared: Option<&mut SharedFutexMapping<'_>>,
    ) -> Result<Option<Served>, FutexRefusal> {
        if frame.x[8] != SYS_FUTEX as u64 {
            return Ok(None);
        }
        let mut call = FutexCall {
            args: crate::sched::args(frame),
        };
        // The same candidate rule as x86's native entry (`serve_native_futex`).
        let candidate = shared.is_some().then(|| call.shared_private_candidate());
        let mut authenticate = match candidate.flatten() {
            Some(candidate) => {
                call = candidate;
                shared
            }
            None => None,
        };
        if !call.admitted() {
            return Ok(None);
        }
        let shared = authenticate.is_some();
        // A wake has no expiry to retain and finishes once policy runs, so
        // its mapping is authenticated first (as #1941 does on x86).
        let wake = call.args[1] == FUTEX_WAKE_PRIVATE || call.args[1] == FUTEX_WAKE_BITSET_PRIVATE;
        if wake && let Some(authenticate) = authenticate.take() {
            match authenticate(UserVa::new(call.args[0]), None) {
                Ok(true) => {}
                Ok(false) => return Ok(None),
                Err(outcome) => return Err(FutexRefusal::Mapping(outcome)),
            }
        }
        let mut adapter = Adapter {
            sched: self,
            frame,
            refusal: None,
            operation,
            shared,
            authenticate,
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
