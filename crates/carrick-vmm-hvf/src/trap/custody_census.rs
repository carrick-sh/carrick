//! Test teardown census: no carrier stage-2 record outlives its custody or
//! the test that registered it.
//!
//! A record's owner removes it when the owner goes (production retirement,
//! a lease's abandonment, a VM's destroy settlement). A record still present
//! when its custody drops, or still present in the process-wide legacy test
//! custody after the test that registered it finished, has no owner left:
//! it leaks into every later lookup over its IPA (the wider non-live record
//! that hid an import's live record, #3035 round 31).
//!
//! Every record is stamped at indexing with the registering test thread.
//! The census never panics where a panic could abort the run (a `Drop`, or
//! the middle of an unrelated test that holds leases whose own drops
//! assert): it only collects, and asserts once at a safe point.
//! - A dropped custody with any record left adds them to the report.
//! - One test, `zzz_custody_census`, runs after every other test of the lib
//!   (libtest runs tests in name order, and the lib runs serially). It scans
//!   the process-wide legacy custody for any record another test registered
//!   (each named by its registering test thread), then fails once, listing
//!   every leaker with its records' real values.
use super::carrier_custody::{CarrierStage2RecordId, CarrierStage2Records};

/// The registering thread of each live record of one custody.
#[derive(Debug, Default)]
pub(crate) struct RecordCensus {
    registered_by: std::collections::BTreeMap<CarrierStage2RecordId, String>,
}

impl RecordCensus {
    pub(crate) fn stamp(&mut self, id: CarrierStage2RecordId) {
        let name = std::thread::current()
            .name()
            .unwrap_or("<unnamed>")
            .to_owned();
        self.registered_by.insert(id, name);
    }

    pub(crate) fn forget(&mut self, id: CarrierStage2RecordId) {
        self.registered_by.remove(&id);
    }

    pub(crate) fn registered_by(&self, id: CarrierStage2RecordId) -> Option<&str> {
        self.registered_by.get(&id).map(String::as_str)
    }
}

/// One line per record in `records` registered by a thread `select` admits.
fn leaked_records(
    records: &CarrierStage2Records,
    where_found: &str,
    select: impl Fn(&str) -> bool,
) -> Vec<String> {
    records
        .stage2_records
        .iter()
        .filter_map(|(id, record)| {
            let thread = records.census.registered_by(*id).unwrap_or("<unstamped>");
            select(thread).then(|| {
                format!(
                    "{where_found}: record {} registered by {thread}: {:?} (unmap in flight: {}, \
                     installed: {})",
                    id.0,
                    record.snapshot,
                    record.unmap_in_flight,
                    records.installed.contains_key(id),
                )
            })
        })
        .collect()
}

/// Every leak seen so far, deduplicated (a legacy leak can be seen by both
/// its thread's teardown and the final scan).
static REPORTED: parking_lot::Mutex<std::collections::BTreeSet<String>> =
    parking_lot::Mutex::new(std::collections::BTreeSet::new());

/// Collect the records a dropping custody still holds. Never panics.
pub(crate) fn collect_custody_drop_leaks(records: &CarrierStage2Records) {
    let dropper = std::thread::current()
        .name()
        .unwrap_or("<unnamed>")
        .to_owned();
    let leaked = leaked_records(records, &format!("custody dropped by {dropper}"), |_| true);
    if !leaked.is_empty() {
        REPORTED.lock().extend(leaked);
    }
}

/// The census's one assertion, for the test that runs after every other:
/// any record another test registered and left in the legacy custody, plus
/// everything collected, fails it with the full list.
pub(crate) fn assert_no_leak() {
    let me = std::thread::current().name().map(str::to_owned);
    if let Some(legacy) = super::legacy_test_carrier_vm_custody_if_created() {
        let leaked = leaked_records(&legacy.stage2.lock(), "legacy custody", |stamp| {
            Some(stamp) != me.as_deref()
        });
        REPORTED.lock().extend(leaked);
    }
    let reported = std::mem::take(&mut *REPORTED.lock());
    assert!(
        reported.is_empty(),
        "custody census: {} stage-2 record(s) outlived their test or custody:\n{}",
        reported.len(),
        reported.into_iter().collect::<Vec<_>>().join("\n")
    );
}
