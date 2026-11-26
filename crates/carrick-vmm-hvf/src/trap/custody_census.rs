//! Test teardown census: no carrier stage-2 record outlives its custody or
//! the test that registered it.
//!
//! A record's owner removes it when the owner goes (production retirement,
//! a lease's abandonment, a VM's destroy settlement). A record still present
//! when its custody drops, or still present in the process-wide legacy test
//! custody when the test thread that registered it exits, has no owner left:
//! it leaks into every later lookup over its IPA (the wider non-live record
//! that hid an import's live record, #3035 round 31).
//!
//! Every record is stamped at indexing with the registering test thread.
//! - A dropped custody with any record left panics in the dropping test.
//! - A libtest thread (named after its test) arms a thread-local whose
//!   destructor runs when the test returns, before the next test starts
//!   under `RUST_TEST_THREADS=1`. It reports any legacy-custody record that
//!   thread registered and left behind, and the next test that takes the
//!   legacy custody fails with the leaker's name and the records' real
//!   values. The report is drained, so one leak fails one test.
use super::carrier_custody::{CarrierStage2RecordId, CarrierStage2Records};

/// The registering thread of each live record of one custody.
#[derive(Debug, Default)]
pub(crate) struct RecordCensus {
    registered_by: std::collections::BTreeMap<CarrierStage2RecordId, String>,
}

impl RecordCensus {
    pub(crate) fn stamp(&mut self, id: CarrierStage2RecordId) {
        let thread = std::thread::current();
        let name = thread.name().unwrap_or("<unnamed>").to_owned();
        if is_test_thread(&name) {
            TEARDOWN.with(|_| {});
        }
        self.registered_by.insert(id, name);
    }

    pub(crate) fn forget(&mut self, id: CarrierStage2RecordId) {
        self.registered_by.remove(&id);
    }

    pub(crate) fn registered_by(&self, id: CarrierStage2RecordId) -> Option<&str> {
        self.registered_by.get(&id).map(String::as_str)
    }
}

/// libtest names each test's thread after the test's module path; helper
/// threads a test spawns are unnamed or carry a plain name, and their
/// records are the test's to settle, so only the test thread is checked.
fn is_test_thread(name: &str) -> bool {
    name.contains("::")
}

/// One line per record in `records` registered by a thread `select` admits.
pub(crate) fn leaked_records(
    records: &CarrierStage2Records,
    select: impl Fn(&str) -> bool,
) -> Vec<String> {
    records
        .stage2_records
        .iter()
        .filter_map(|(id, record)| {
            let thread = records.census.registered_by(*id).unwrap_or("<unstamped>");
            select(thread).then(|| {
                format!(
                    "record {} registered by {thread}: {:?} (unmap in flight: {}, installed: {})",
                    id.0,
                    record.snapshot,
                    record.unmap_in_flight,
                    records.installed.contains_key(id),
                )
            })
        })
        .collect()
}

/// Fail a custody's drop if any record outlives it.
pub(crate) fn assert_custody_drop_leaves_no_record(records: &CarrierStage2Records) {
    if std::thread::panicking() {
        return;
    }
    let leaked = leaked_records(records, |_| true);
    assert!(
        leaked.is_empty(),
        "custody census: {} stage-2 record(s) outlive their custody:\n{}",
        leaked.len(),
        leaked.join("\n")
    );
}

static REPORTED: parking_lot::Mutex<Vec<String>> = parking_lot::Mutex::new(Vec::new());

/// Fail the caller with every leak a finished test left in the legacy
/// custody, then forget them: one leak fails one test.
pub(crate) fn assert_no_reported_legacy_leak() {
    let reported = std::mem::take(&mut *REPORTED.lock());
    assert!(
        reported.is_empty(),
        "custody census: a finished test left {} stage-2 record(s) in the shared legacy \
         test custody:\n{}",
        reported.len(),
        reported.join("\n")
    );
}

struct Teardown;

impl Drop for Teardown {
    fn drop(&mut self) {
        let thread = std::thread::current();
        let Some(name) = thread.name().map(str::to_owned) else {
            return;
        };
        let Some(legacy) = super::legacy_test_carrier_vm_custody_if_created() else {
            return;
        };
        let leaked = leaked_records(&legacy.stage2.lock(), |stamp| stamp == name);
        if !leaked.is_empty() {
            REPORTED.lock().extend(leaked);
        }
    }
}

thread_local! {
    static TEARDOWN: Teardown = const { Teardown };
}
