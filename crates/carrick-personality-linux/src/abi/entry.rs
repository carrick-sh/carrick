//! Linux task, entry diagnostics and host-completion state.
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

pub const SERVED_WAKES_OWED: u32 = 1;
pub const SERVED_COMMIT_OWED: u32 = 2;

#[repr(C, align(8))]
#[derive(Debug)]
pub struct LinuxTaskState {
    pub file_table: AtomicU64,
    pub fixup_pc: AtomicU64,
    pub orig_arg0: AtomicU64,
    pub pending_host_work: AtomicU32,
    pub served_with_work: AtomicU32,
}
impl LinuxTaskState {
    pub const fn new() -> Self {
        Self {
            file_table: AtomicU64::new(0),
            fixup_pc: AtomicU64::new(0),
            orig_arg0: AtomicU64::new(0),
            pending_host_work: AtomicU32::new(0),
            served_with_work: AtomicU32::new(0),
        }
    }
    pub fn has_pending_host_work(&self) -> bool {
        self.pending_host_work.load(Ordering::Acquire) != 0
    }
    pub fn mark_pending_host_work(&self) {
        self.pending_host_work.store(1, Ordering::Release);
    }
    pub fn clear_pending_host_work(&self) {
        self.pending_host_work.store(0, Ordering::Release);
    }
    pub fn take_served_boundary(&self) -> Option<ServedBoundary> {
        match self.served_with_work.swap(0, Ordering::AcqRel) {
            0 => None,
            SERVED_COMMIT_OWED => Some(ServedBoundary::ReplayOriginal {
                x0: self.orig_arg0.load(Ordering::Relaxed),
            }),
            _ => Some(ServedBoundary::Completed),
        }
    }
    /// A wake cannot downgrade a previously owed metadata commit.
    pub fn record_completed_with_work(&self) {
        self.served_with_work
            .fetch_max(SERVED_WAKES_OWED, Ordering::AcqRel);
    }
    /// Only this Linux disposition permits original-argument replay.
    pub fn record_commit_owed(&self, orig_arg0: u64) {
        self.orig_arg0.store(orig_arg0, Ordering::Relaxed);
        self.served_with_work
            .store(SERVED_COMMIT_OWED, Ordering::Release);
    }
}
impl Default for LinuxTaskState {
    fn default() -> Self {
        Self::new()
    }
}

#[repr(C, align(8))]
#[derive(Debug)]
pub struct LinuxTaskMetadata {
    pub lifecycle_page: AtomicU64,
    pub control_slot: AtomicU64,
}
impl LinuxTaskMetadata {
    pub const fn new() -> Self {
        Self {
            lifecycle_page: AtomicU64::new(0),
            control_slot: AtomicU64::new(0),
        }
    }
}
impl Default for LinuxTaskMetadata {
    fn default() -> Self {
        Self::new()
    }
}
const _: () = {
    assert!(core::mem::size_of::<LinuxTaskState>() == 32);
    assert!(core::mem::offset_of!(LinuxTaskState, file_table) == 0);
    assert!(core::mem::offset_of!(LinuxTaskState, fixup_pc) == 8);
    assert!(core::mem::offset_of!(LinuxTaskState, orig_arg0) == 16);
    assert!(core::mem::offset_of!(LinuxTaskState, pending_host_work) == 24);
    assert!(core::mem::offset_of!(LinuxTaskState, served_with_work) == 28);
    assert!(core::mem::size_of::<LinuxTaskMetadata>() == 16);
};

/// What a thread owes the host after EL1 served its syscall with work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServedBoundary {
    /// The call is complete; only owed wakes are delivered. The guest
    /// resumes after the syscall instruction.
    Completed,
    /// EL1 edited the guest tables but the host must still commit the call's
    /// metadata. The host runs the call again, and it must see the ORIGINAL
    /// arguments: EL1 overwrote x0 with the result, so `x0` here is the
    /// argument 0 EL1 preserved. Never re-read x0 from the mutated frame.
    ReplayOriginal { x0: u64 },
}

/// Ordinal in the Linux personality's AArch64-shaped dispatch namespace.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct CanonicalOrdinal(u64);
impl CanonicalOrdinal {
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }
    pub const fn raw(self) -> u64 {
        self.0
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CanonicalCall {
    pub isa: carrick_guest_arch::GuestIsa,
    pub canonical: CanonicalOrdinal,
    pub native: carrick_guest_arch::NativeOrdinal,
    /// Register arguments stay raw until the common personality interprets them.
    pub args: [u64; 6],
    pub stack: carrick_guest_arch::UserVa,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyscallResult(i64);
impl SyscallResult {
    pub const fn new(result: i64) -> Self {
        Self(result)
    }
    pub const fn raw(self) -> i64 {
        self.0
    }
}
