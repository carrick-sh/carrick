//! Terminal diagnostics for a backend stage-2 rollback invariant.
//!
//! The VMM cannot depend on the shared kernel's event ring. The runtime
//! installs this one-way reporter when it binds those layers; a backend which
//! must quarantine a record can then leave durable terminal evidence without
//! acquiring kernel authority or inventing a second error path.

use std::sync::OnceLock;

/// A never-published stage-2 record lost the RAII authority which alone may
/// retire it. The record remains quarantined and is never reissued.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Stage2RollbackInvariant {
    pub record_id: u64,
    pub vm_generation: u64,
    pub logical_owner: u64,
}

type Reporter = fn(Stage2RollbackInvariant);

static REPORTER: OnceLock<Reporter> = OnceLock::new();

/// Install the carrier's terminal event-ring reporter. Returns `true` only
/// for the process's first installation.
pub fn install_stage2_rollback_invariant_reporter(reporter: Reporter) -> bool {
    REPORTER.set(reporter).is_ok()
}

/// Publish a terminal rollback invariant when a reporter is installed.
///
/// The record remains safely quarantined even before runtime initialization;
/// the reporter adds diagnostics and is not part of the safety mechanism.
pub fn report_stage2_rollback_invariant(event: Stage2RollbackInvariant) {
    if let Some(reporter) = REPORTER.get() {
        reporter(event);
    }
}
