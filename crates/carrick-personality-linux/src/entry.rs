//! Linux decoding and dispatch at the shared native-entry seam.
pub use crate::abi::entry::{CanonicalCall, CanonicalOrdinal, SyscallResult};
use carrick_core_abi::EntryMmKey;
pub use carrick_core_abi::ExecutionBinding;
use carrick_guest_arch::{
    GuestIsa, NativeAbi, NativeEntrySnapshot, NativeOrdinal, UserVa, X86Register, X86Registers,
};

pub const SYS_SET_ROBUST_LIST: usize = 99;
pub const EINVAL: i64 = -22;

/// Decode the Linux x86_64 syscall ABI from a native register snapshot.
pub fn decode_x86_64(native: u64, mut args: [u64; 6], stack: u64) -> CanonicalCall {
    let canonical = match native {
        273 => SYS_SET_ROBUST_LIST as u64,
        56 => {
            args.swap(3, 4);
            220
        }
        60 => 93,
        186 => 178,
        14 => 135,
        131 => 132,
        202 => 98,
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
    fn lifecycle_native(&mut self) -> Option<&mut dyn crate::lifecycle::LifecycleNative<'a>> {
        Some(self)
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

impl crate::lifecycle::UserCopy for CommonFamilies<'_> {
    fn copy_in(&mut self, _: &mut [u8], _: u64) -> bool {
        false
    }
    fn copy_out(&mut self, _: u64, _: &[u8]) -> bool {
        false
    }
}
impl<'a> crate::lifecycle::LifecycleNative<'a> for CommonFamilies<'a> {
    fn arguments(&self) -> [u64; 6] {
        self.args
    }
    fn binding(&self) -> Option<ExecutionBinding> {
        Some(self.venue.binding())
    }
    fn task_state(&self) -> Option<&'a crate::abi::entry::LinuxTaskState> {
        Some(self.venue.task_state())
    }
    fn register_robust_list(&self, head: u64, len: u64) -> Option<SyscallResult> {
        self.venue
            .set_robust_list(head, len)
            .map(SyscallResult::new)
    }
    fn thread(&self) -> Option<crate::thread::LifecycleThread<'a>> {
        None
    }
    fn born_slot(
        &self,
        _: &crate::abi::thread::ThreadLifecyclePage,
        _: carrick_core_abi::EntryRef,
    ) -> Option<&'a crate::abi::thread::ThreadControlSlot> {
        None
    }
    fn record_decline(&self, _: crate::abi::thread::LifecycleDecline) {}
    fn has_scheduler(&self) -> bool {
        false
    }
    fn user_sp(&mut self) -> Option<UserVa> {
        None
    }
    fn affinity(&self) -> Option<u64> {
        None
    }
    fn allocate_record(
        &mut self,
        _: carrick_sched_core::ThreadIdentity,
    ) -> Result<carrick_sched_core::RecordRef, carrick_sched_core::Exhausted> {
        Err(carrick_sched_core::Exhausted)
    }
    fn free_record(&mut self, _: carrick_sched_core::RecordRef) {}
    fn prepare_child(
        &mut self,
        _: carrick_sched_core::RecordRef,
        _: crate::lifecycle::ChildContext,
    ) {
    }
    fn enqueue_born(&mut self, _: carrick_sched_core::RecordRef) {}
    fn exit_record(&self) -> Option<crate::lifecycle::ExitRecord> {
        None
    }
    fn wake_child_tid(&mut self, _: EntryMmKey, _: UserVa) -> bool {
        false
    }
    fn release_current(&mut self, _: carrick_sched_core::RecordRef) {}
    fn run_next(&mut self, _: SyscallResult) -> (carrick_core::Served, SyscallResult) {
        (
            carrick_core::Served::Idle,
            SyscallResult::new(self.result.unwrap_or(0)),
        )
    }
    fn result(&self) -> SyscallResult {
        SyscallResult::new(self.result.unwrap_or(self.args[0] as i64))
    }
    fn set_result(&mut self, result: SyscallResult) {
        self.result = Some(result.raw());
    }
}
