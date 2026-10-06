//! Linux decoding and dispatch at the shared native-entry seam.
use carrick_core_abi::EntryCompletion;
pub use carrick_core_abi::ExecutionBinding;
use carrick_guest_arch::{CanonicalCall, CanonicalOrdinal, GuestIsa, NativeOrdinal, UserVa};

pub use carrick_guest_arch::SyscallResult;

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

struct CommonFamilies<'a> {
    venue: &'a dyn LinuxEntryVenue,
    args: [u64; 6],
    result: Option<i64>,
}
impl crate::dispatch::PendingFamilies for CommonFamilies<'_> {
    fn lifecycle(&mut self, ordinal: u64) -> crate::dispatch::FamilyCompletion {
        if ordinal != SYS_SET_ROBUST_LIST as u64 {
            return crate::dispatch::FamilyCompletion::Forward;
        }
        self.result = self.venue.set_robust_list(self.args[0], self.args[1]);
        self.result.map_or(
            crate::dispatch::FamilyCompletion::Forward,
            crate::dispatch::FamilyCompletion::Complete,
        )
    }
    fn lifecycle_available(&self) -> bool {
        true
    }
    fn host_work(&self) -> bool {
        self.venue.pending_work()
    }
    fn record_served(&self, ordinal: u64) {
        self.venue.record_served(ordinal as usize);
    }
    fn record_forwarded(&self, ordinal: u64) {
        self.venue.record_forwarded(ordinal as usize);
    }
    fn publish_work(&self, _: bool) {
        self.venue.mark_completed_with_work();
    }
}

pub fn serve(call: &CanonicalCall, venue: &dyn LinuxEntryVenue) -> EntryOutcome {
    let Ok(nr) = usize::try_from(call.canonical.raw()) else {
        return EntryOutcome::Forward;
    };
    let Some(completion) = carrick_core::entry::admit(venue.binding()) else {
        venue.record_forwarded(nr);
        return EntryOutcome::Forward;
    };
    let mut pending = CommonFamilies {
        venue,
        args: call.args,
        result: None,
    };
    let route = crate::dispatch::dispatch(call.canonical.raw(), u64::MAX, &mut pending);
    let Some(result) = pending.result else {
        return EntryOutcome::Forward;
    };
    let result = SyscallResult::new(result);
    match route {
        crate::dispatch::CompletionRoute::Served => EntryOutcome::Served { result, completion },
        crate::dispatch::CompletionRoute::WithWork => {
            EntryOutcome::ServedWithWork { result, completion }
        }
        _ => EntryOutcome::Forward,
    }
}
