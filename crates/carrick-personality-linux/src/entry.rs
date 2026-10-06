//! Linux decoding and dispatch at the shared native-entry seam.
use carrick_core_abi::EntryCompletion;
pub use carrick_core_abi::ExecutionBinding;
use carrick_guest_arch::{
    CanonicalCall, CanonicalOrdinal, GuestIsa, NativeOrdinal, SyscallResult, UserVa,
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

#[derive(Debug, Eq, PartialEq)]
pub enum EntryOutcome {
    Served {
        result: SyscallResult,
        completion: EntryCompletion,
    },
    ServedWithWork {
        result: SyscallResult,
        completion: EntryCompletion,
    },
    Forward,
}

pub trait LinuxEntryVenue {
    fn binding(&self) -> ExecutionBinding;
    fn set_robust_list(&self, head: u64, len: u64) -> Option<i64>;
    fn pending_work(&self) -> bool;
    fn record_forwarded(&self, ordinal: usize);
    fn record_served(&self, ordinal: usize);
    fn mark_completed_with_work(&self);
}

pub fn serve(call: &CanonicalCall, venue: &dyn LinuxEntryVenue) -> EntryOutcome {
    let Ok(nr) = usize::try_from(call.canonical.raw()) else {
        return EntryOutcome::Forward;
    };
    let Some(completion) = EntryCompletion::admit(venue.binding()) else {
        venue.record_forwarded(nr);
        return EntryOutcome::Forward;
    };
    let result = match nr {
        SYS_SET_ROBUST_LIST => venue.set_robust_list(call.args[0], call.args[1]),
        _ => None,
    };
    let Some(result) = result else {
        venue.record_forwarded(nr);
        return EntryOutcome::Forward;
    };
    venue.record_served(nr);
    let result = SyscallResult::new(result);
    if venue.pending_work() {
        venue.mark_completed_with_work();
        EntryOutcome::ServedWithWork { result, completion }
    } else {
        EntryOutcome::Served { result, completion }
    }
}
