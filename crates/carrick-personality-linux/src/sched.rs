//! Linux futex decoding, timeout admission and completion values.
use crate::dispatch::FamilyCompletion;
use crate::entry::SyscallResult;
use carrick_core_abi::ReservationMm;
use carrick_guest_arch::{CounterTick, UserVa};
use carrick_syscall_abi::{
    LINUX_EFAULT, LINUX_EINVAL, LINUX_ESRCH, LINUX_SCHED_BATCH, LINUX_SCHED_DEADLINE,
    LINUX_SCHED_FIFO, LINUX_SCHED_IDLE, LINUX_SCHED_OTHER, LINUX_SCHED_OTHER_SLICE_BYTES,
    LINUX_SCHED_RR, LinuxErrno,
};

#[derive(Clone, Copy)]
pub struct FutexFrequency(u64);
impl FutexFrequency {
    pub const fn from_hz(hz: u64) -> Self {
        Self(hz)
    }
    pub const fn hz(self) -> u64 {
        self.0
    }
}
pub const SYS_FUTEX: usize = 98;
pub const FUTEX_WAIT_PRIVATE: u64 = 128;
pub const FUTEX_WAKE_PRIVATE: u64 = 129;
pub const FUTEX_WAIT_BITSET_PRIVATE: u64 = 128 | 9;
pub const FUTEX_WAKE_BITSET_PRIVATE: u64 = 128 | 10;
pub const EAGAIN: i64 = -11;
pub const ETIMEDOUT_RESULT: u64 = (-110_i64) as u64;

/// Linux register arguments after the native adapter has captured them.
#[derive(Clone, Copy)]
pub struct FutexCall {
    pub args: [u64; 6],
}
impl FutexCall {
    pub fn admitted(self) -> bool {
        if self.args[0] & 3 != 0 {
            return false;
        }
        match self.args[1] {
            FUTEX_WAIT_PRIVATE => true,
            FUTEX_WAIT_BITSET_PRIVATE => self.args[3] == 0 && self.args[5] as u32 != 0,
            FUTEX_WAKE_PRIVATE => self.args[2] as i32 > 0,
            FUTEX_WAKE_BITSET_PRIVATE => self.args[2] as i32 > 0 && self.args[5] as u32 != 0,
            _ => false,
        }
    }
}

/// Native context and clock hooks over the existing wait owner. No new wait
/// ledger or runnable graph is created by this Linux client.
pub trait FutexVenue {
    type Served;
    fn mm(&self) -> Option<ReservationMm>;
    fn timed_wait_allowed(&self) -> bool;
    fn read_u64(&self, address: UserVa) -> Option<u64>;
    fn frequency(&self) -> FutexFrequency;
    fn now(&self) -> CounterTick;
    fn wake(
        &mut self,
        mm: ReservationMm,
        address: UserVa,
        bitset: u32,
        limit: u32,
    ) -> Option<Self::Served>;
    fn wait(&mut self, wait: FutexWait) -> Option<Self::Served>;
}

pub struct FutexWait {
    pub mm: ReservationMm,
    pub address: UserVa,
    pub bitset: u32,
    pub expected: u32,
    pub deadline: Option<CounterTick>,
    pub mismatch_result: SyscallResult,
    pub timeout_result: SyscallResult,
}

pub fn serve_futex<V: FutexVenue>(call: FutexCall, venue: &mut V) -> Option<V::Served> {
    let mm = venue.mm()?;
    if !call.admitted() {
        return None;
    }
    let [address, op, expected, timeout, _, mask] = call.args;
    let address = UserVa::new(address);
    let bitset = if matches!(op, FUTEX_WAIT_PRIVATE | FUTEX_WAKE_PRIVATE) {
        u32::MAX
    } else {
        mask as u32
    };
    if matches!(op, FUTEX_WAKE_PRIVATE | FUTEX_WAKE_BITSET_PRIVATE) {
        return venue.wake(mm, address, bitset, expected as i32 as u32);
    }
    let deadline = if timeout != 0 {
        if !venue.timed_wait_allowed() {
            return None;
        }
        let secs = venue.read_u64(UserVa::new(timeout))? as i64;
        let nanos = venue.read_u64(UserVa::new(timeout + 8))? as i64;
        if secs < 0 || !(0..1_000_000_000).contains(&nanos) {
            return None;
        }
        let nanos_ticks =
            (u128::from(nanos as u64) * u128::from(venue.frequency().hz()) / 1_000_000_000) as u64;
        let ticks = (secs as u64)
            .saturating_mul(venue.frequency().hz())
            .saturating_add(nanos_ticks);
        Some(CounterTick::new(
            venue.now().raw().saturating_add(ticks).max(1),
        ))
    } else {
        None
    };
    venue.wait(FutexWait {
        mm,
        address,
        bitset,
        expected: expected as u32,
        deadline,
        mismatch_result: SyscallResult::new(EAGAIN),
        timeout_result: SyscallResult::new(ETIMEDOUT_RESULT as i64),
    })
}

pub fn is_served_futex_op(ordinal: u64, args: [u64; 6]) -> bool {
    ordinal == SYS_FUTEX as u64 && FutexCall { args }.admitted()
}

/// Scheduling calls served directly in-ring.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SchedCall {
    GetPriorityMax,
    GetPriorityMin,
    RrGetInterval,
}

/// Execution venue and guest memory access for in-ring scheduling operations.
pub trait SchedVenue {
    fn argument(&self, index: usize) -> u64;
    fn current_pid(&self) -> Option<u32> {
        None
    }
    fn copy_out(&mut self, dst: UserVa, src: &[u8]) -> bool {
        let _ = (dst, src);
        false
    }
}

pub fn sched_priority_min(policy: i32) -> Result<i64, LinuxErrno> {
    match policy {
        LINUX_SCHED_OTHER | LINUX_SCHED_BATCH | LINUX_SCHED_IDLE | LINUX_SCHED_DEADLINE => Ok(0),
        LINUX_SCHED_FIFO | LINUX_SCHED_RR => Ok(1),
        _ => Err(LINUX_EINVAL),
    }
}

pub fn sched_priority_max(policy: i32) -> Result<i64, LinuxErrno> {
    match policy {
        LINUX_SCHED_OTHER | LINUX_SCHED_BATCH | LINUX_SCHED_IDLE | LINUX_SCHED_DEADLINE => Ok(0),
        LINUX_SCHED_FIFO | LINUX_SCHED_RR => Ok(99),
        _ => Err(LINUX_EINVAL),
    }
}

pub fn serve_sched(call: SchedCall, venue: &mut dyn SchedVenue) -> FamilyCompletion {
    match call {
        SchedCall::GetPriorityMax => {
            let policy = venue.argument(0) as i32;
            match sched_priority_max(policy) {
                Ok(max) => FamilyCompletion::Complete(max),
                Err(err) => FamilyCompletion::Complete(err.guest_retval()),
            }
        }
        SchedCall::GetPriorityMin => {
            let policy = venue.argument(0) as i32;
            match sched_priority_min(policy) {
                Ok(min) => FamilyCompletion::Complete(min),
                Err(err) => FamilyCompletion::Complete(err.guest_retval()),
            }
        }
        SchedCall::RrGetInterval => {
            let pid = venue.argument(0) as i32;
            let interval = venue.argument(1);
            if pid < 0 {
                return FamilyCompletion::Complete(LINUX_EINVAL.guest_retval());
            }
            if interval == 0 {
                return FamilyCompletion::Complete(LINUX_EFAULT.guest_retval());
            }
            if pid != 0 {
                let self_pid = venue.current_pid().unwrap_or(0) as i32;
                if pid != self_pid {
                    return FamilyCompletion::Complete(LINUX_ESRCH.guest_retval());
                }
            }
            if !venue.copy_out(UserVa::new(interval), &LINUX_SCHED_OTHER_SLICE_BYTES) {
                return FamilyCompletion::Complete(LINUX_EFAULT.guest_retval());
            }
            FamilyCompletion::Complete(0)
        }
    }
}
