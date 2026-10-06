//! Linux decoding and dispatch at the shared native-entry seam.
pub use crate::abi::entry::{CanonicalCall, CanonicalOrdinal, SyscallResult};
pub use carrick_core_abi::ExecutionBinding;
use carrick_guest_arch::{
    GuestIsa, NativeAbi, NativeEntrySnapshot, NativeOrdinal, UserVa, X86Register, X86Registers,
};

pub const SYS_SET_ROBUST_LIST: usize = 99;
pub const EINVAL: i64 = -22;

/// Decode the Linux x86_64 syscall ABI from a native register snapshot.
pub fn decode_x86_64(native: u64, args: [u64; 6], stack: u64) -> CanonicalCall {
    let canonical = match native {
        273 => SYS_SET_ROBUST_LIST as u64,
        _ => u64::MAX,
    };
    CanonicalCall {
        isa: GuestIsa::X86_64,
        canonical: CanonicalOrdinal::new(canonical),
        native: NativeOrdinal::new(native),
        args,
        stack: UserVa::new(stack),
    }
}

/// Decode Linux registers from the full native snapshot, refusing an ISA or
/// entry-profile mismatch before dispatch or any family effect.
pub fn decode_x86_snapshot<F: X86Registers>(
    snapshot: NativeEntrySnapshot<'_, F>,
) -> Option<CanonicalCall> {
    if snapshot.isa != GuestIsa::X86_64 || snapshot.abi != NativeAbi::X86_64Syscall {
        return None;
    }
    let frame = snapshot.frame;
    Some(decode_x86_64(
        frame.read(X86Register::Rax),
        [
            frame.read(X86Register::Rdi),
            frame.read(X86Register::Rsi),
            frame.read(X86Register::Rdx),
            frame.read(X86Register::R10),
            frame.read(X86Register::R8),
            frame.read(X86Register::R9),
        ],
        frame.read(X86Register::Rsp),
    ))
}

/// The native ARM adapter extracts x8 and supplies Linux's six ABI register
/// arguments. The ordinal is interpreted here, never by the hardware trait.
pub fn decode_aarch64(native: u64, args: [u64; 6], stack: u64) -> CanonicalCall {
    CanonicalCall {
        isa: GuestIsa::Aarch64,
        canonical: CanonicalOrdinal::new(native),
        native: NativeOrdinal::new(native),
        args,
        stack: UserVa::new(stack),
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum EntryOutcome {
    Served { result: SyscallResult },
    ServedWithWork { result: SyscallResult },
    Forward,
    InvalidCompletion,
}

pub trait LinuxEntryVenue {
    fn binding(&self) -> ExecutionBinding;
    fn set_robust_list(&self, head: u64, len: u64) -> Option<i64>;
    fn task_state(&self) -> &crate::abi::entry::LinuxTaskState;
    fn record_forwarded(&self, ordinal: usize);
    fn record_served(&self, ordinal: usize);
}

/// Shared counter/work transport over live native binding and robust-list hooks.
pub struct SharedVenue<'a, B, R> {
    pub binding: B,
    pub state: &'a crate::abi::entry::LinuxTaskState,
    pub counters: crate::dispatch::EntryCounters<'a>,
    pub robust_list: R,
}
impl<B: Fn() -> ExecutionBinding, R: Fn(u64, u64) -> Option<i64>> LinuxEntryVenue
    for SharedVenue<'_, B, R>
{
    fn binding(&self) -> ExecutionBinding {
        (self.binding)()
    }
    fn task_state(&self) -> &crate::abi::entry::LinuxTaskState {
        self.state
    }
    fn set_robust_list(&self, head: u64, len: u64) -> Option<i64> {
        (self.robust_list)(head, len)
    }
    fn record_forwarded(&self, ordinal: usize) {
        self.counters.forwarded(ordinal as u64);
    }
    fn record_served(&self, ordinal: usize) {
        self.counters.served(ordinal as u64);
    }
}

struct CommonFamilies<'a> {
    venue: &'a dyn LinuxEntryVenue,
    args: [u64; 6],
    result: Option<i64>,
}
impl<'a> crate::dispatch::PendingFamilies<'a> for CommonFamilies<'a> {
    fn binding(&self) -> Option<ExecutionBinding> {
        Some(self.venue.binding())
    }
    fn lifecycle(&mut self, ordinal: u64) -> crate::dispatch::FamilyCompletion {
        if ordinal != SYS_SET_ROBUST_LIST as u64 {
            return crate::dispatch::FamilyCompletion::Forward;
        }
        self.result = self.venue.set_robust_list(self.args[0], self.args[1]);
        if self.result.is_some() {
            self.venue
                .task_state()
                .orig_arg0
                .store(self.args[0], core::sync::atomic::Ordering::Relaxed);
        }
        self.result.map_or(
            crate::dispatch::FamilyCompletion::Forward,
            crate::dispatch::FamilyCompletion::Complete,
        )
    }
    fn lifecycle_available(&self) -> bool {
        true
    }
    fn host_work(&self) -> bool {
        self.venue.task_state().has_pending_host_work()
    }
    fn record_served(&self, ordinal: u64) {
        self.venue.record_served(ordinal as usize);
    }
    fn record_forwarded(&self, ordinal: u64) {
        self.venue.record_forwarded(ordinal as usize);
    }
    fn publish_work(&self, _: bool) {
        self.venue.task_state().record_completed_with_work();
    }
}

pub fn serve(call: &CanonicalCall, venue: &dyn LinuxEntryVenue) -> EntryOutcome {
    let Ok(_) = usize::try_from(call.canonical.raw()) else {
        return EntryOutcome::Forward;
    };
    let mut pending = CommonFamilies {
        venue,
        args: call.args,
        result: None,
    };
    let route = crate::dispatch::dispatch(call.canonical.raw(), u64::MAX, &mut pending);
    if route == crate::dispatch::CompletionRoute::InvalidCompletion {
        return EntryOutcome::InvalidCompletion;
    }
    let Some(result) = pending.result else {
        return EntryOutcome::Forward;
    };
    let result = SyscallResult::new(result);
    match route {
        crate::dispatch::CompletionRoute::Served => EntryOutcome::Served { result },
        crate::dispatch::CompletionRoute::WithWork => EntryOutcome::ServedWithWork { result },
        _ => EntryOutcome::Forward,
    }
}
