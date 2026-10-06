//! Linux lifecycle decoding and result policy; native hooks retain order-6 bodies.
use crate::abi::entry::SyscallResult;

pub const SYS_EXIT: usize = 93;
pub const SYS_SIGALTSTACK: usize = 132;
pub const SYS_RT_SIGPROCMASK: usize = 135;
pub const SYS_GETTID: usize = 178;
pub const SYS_CLONE: usize = 220;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleCall {
    Exit,
    SigAltStack,
    SigProcMask,
    SetRobustList,
    GetTid,
    Clone,
}

/// A primitive returns data, never an entry completion or a final frame write.
pub enum LifecycleOutcome {
    Returned {
        result: SyscallResult,
        work: bool,
    },
    Transferred {
        progress: carrick_core_abi::Served,
        result: SyscallResult,
    },
}

pub fn lifecycle_effect(outcome: &LifecycleOutcome) -> crate::dispatch::FamilyCompletion {
    use crate::dispatch::FamilyCompletion;
    match *outcome {
        LifecycleOutcome::Returned { result, work: true } => {
            FamilyCompletion::CompleteWithWork(result.raw())
        }
        LifecycleOutcome::Returned {
            result,
            work: false,
        } => FamilyCompletion::Complete(result.raw()),
        LifecycleOutcome::Transferred {
            progress: carrick_core_abi::Served::Returned { .. },
            result,
        } => FamilyCompletion::Switched(result.raw()),
        LifecycleOutcome::Transferred {
            progress: carrick_core_abi::Served::Idle,
            ..
        } => FamilyCompletion::Suspended,
    }
}

/// `sizeof(struct robust_list_head)` on 64-bit Linux.
pub const ROBUST_LIST_HEAD_SIZE: u64 = 24;

/// A user address stored for exit-time walking, never dereferenced here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RobustListHead(u64);
impl RobustListHead {
    pub const fn new(user_address: u64) -> Self {
        Self(user_address)
    }
    pub const fn raw(self) -> u64 {
        self.0
    }
}

/// Preserve all argument bits before Linux's size comparison.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RobustListLen(u64);
impl RobustListLen {
    pub const fn new(len: u64) -> Self {
        Self(len)
    }
    pub const fn raw(self) -> u64 {
        self.0
    }
}

pub trait RobustListVenue {
    fn setup_enabled(&self) -> bool;
    fn gate_closed(&self) -> bool;
    fn publish(&self, head: RobustListHead, len: u32);
    fn publication_counter(&self) -> Option<&core::sync::atomic::AtomicU64>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RobustListOutcome {
    Registered,
    InvalidLength,
    Declined,
}
impl RobustListOutcome {
    pub const fn linux_result(self) -> Option<i64> {
        match self {
            Self::Registered => Some(0),
            Self::InvalidLength => Some(crate::entry::EINVAL),
            Self::Declined => None,
        }
    }
}

/// Gate refusal precedes length validation and leaves the owned slot untouched.
pub fn set_robust_list(
    venue: &impl RobustListVenue,
    head: RobustListHead,
    len: RobustListLen,
) -> RobustListOutcome {
    if !venue.setup_enabled() || venue.gate_closed() {
        return RobustListOutcome::Declined;
    }
    if len.raw() != ROBUST_LIST_HEAD_SIZE {
        return RobustListOutcome::InvalidLength;
    }
    venue.publish(head, ROBUST_LIST_HEAD_SIZE as u32);
    if let Some(count) = venue.publication_counter() {
        count.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    }
    RobustListOutcome::Registered
}
