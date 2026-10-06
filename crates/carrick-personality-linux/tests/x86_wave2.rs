use carrick_core::entry::complete;
use carrick_core_abi::ExecutionBinding;
use carrick_personality_linux::dispatch::{
    FamilyCompletion, PendingFamilies, dispatch_aarch64_family,
};
use carrick_personality_linux::entry::{EntryOutcome, LinuxEntryVenue, decode_x86_64, serve};
use core::cell::Cell;

struct Venue {
    binding: ExecutionBinding,
    pending: bool,
    publications: Cell<u64>,
    forwards: Cell<u64>,
    completions_with_work: Cell<u64>,
}

impl LinuxEntryVenue for Venue {
    fn binding(&self) -> ExecutionBinding {
        self.binding
    }
    fn set_robust_list(&self, _: u64, len: u64) -> Option<i64> {
        if len == 24 {
            self.publications.set(self.publications.get() + 1);
            Some(0)
        } else {
            Some(-22)
        }
    }
    fn pending_work(&self) -> bool {
        self.pending
    }
    fn record_forwarded(&self, _: usize) {
        self.forwards.set(self.forwards.get() + 1);
    }
    fn record_served(&self, _: usize) {}
    fn mark_completed_with_work(&self) {
        self.completions_with_work
            .set(self.completions_with_work.get() + 1);
    }
}

#[test]
fn x4_linux_common_entry() {
    let first = ExecutionBinding {
        task: 41,
        generation: 1,
        mm: 5,
        thread_generation: 9,
    };
    let venue = Venue {
        binding: first,
        pending: true,
        publications: Cell::new(0),
        forwards: Cell::new(0),
        completions_with_work: Cell::new(0),
    };
    let call = decode_x86_64(273, [0xa000, 24, 0, 0, 0, 0], 0x7fff_0000);
    let completion = match serve(&call, &venue) {
        EntryOutcome::ServedWithWork { result, completion } => {
            assert_eq!(result.raw(), 0);
            completion
        }
        other => panic!("unexpected entry outcome: {other:?}"),
    };
    assert_eq!(venue.publications.get(), 1);
    assert_eq!(venue.completions_with_work.get(), 1);
    assert!(complete(completion, first).is_ok());

    let reused = ExecutionBinding {
        generation: 2,
        thread_generation: 10,
        ..first
    };
    let stale = carrick_core_abi::EntryCompletion::admit(first).unwrap();
    assert!(complete(stale, reused).is_err());

    let unported = decode_x86_64(39, [0; 6], 0x7fff_0000);
    assert_eq!(serve(&unported, &venue), EntryOutcome::Forward);
    assert_eq!(venue.publications.get(), 1);
    assert_eq!(venue.forwards.get(), 1);
}

struct PendingFile {
    calls: Cell<u64>,
}

impl PendingFamilies for PendingFile {
    fn file_positioned(&mut self, _: u64) -> FamilyCompletion {
        self.calls.set(self.calls.get() + 1);
        FamilyCompletion::Complete(17)
    }
}

#[test]
fn unmigrated_family_completes_once_through_linux_owner() {
    let mut pending = PendingFile {
        calls: Cell::new(0),
    };
    let result = dispatch_aarch64_family(67, u64::MAX, &mut pending);
    assert_eq!(result, FamilyCompletion::Complete(17));
    assert_eq!(pending.calls.get(), 1);
}
