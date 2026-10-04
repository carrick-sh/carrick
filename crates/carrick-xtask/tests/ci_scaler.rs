#![allow(clippy::unwrap_used, clippy::expect_used)]
use carrick_xtask::ci_scaler::*;

fn job(id: u64) -> JobKey {
    JobKey {
        run: RunId(10),
        attempt: 1,
        job: JobId(id),
    }
}
fn vm(id: u16, name: &str) -> Vm {
    Vm {
        id,
        name: name.into(),
        pool: "carrick-ci".into(),
        template: false,
    }
}

#[test]
fn clone_range_cannot_deserialize_protected_or_template_ids() {
    for id in [105, 106, 210, 211, 299, 300, 307, 350] {
        assert!(serde_json::from_str::<CloneId>(&id.to_string()).is_err());
    }
    for id in [308, 349] {
        assert!(serde_json::from_str::<CloneId>(&id.to_string()).is_ok());
    }
}

#[test]
fn ledger_reserves_before_api_and_counts_booting_and_deduplicates() {
    let mut ledger = Ledger::default();
    let row = ledger.reserve(job(20), &[], 100).unwrap();
    assert_eq!(row.vm.get(), 308);
    assert!(ledger.reserve(job(20), &[], 101).is_err());
    assert!(ledger.reserve(job(21), &[], 101).is_err());
    let saved = serde_json::to_vec(&ledger).unwrap();
    let restored: Ledger = serde_json::from_slice(&saved).unwrap();
    assert_eq!(restored.rows.len(), 1);
    assert_eq!(restored.rows[0].state, State::Reserved);
}

#[test]
fn existing_unknown_clone_blocks_admission_even_without_ledger_entry() {
    let mut ledger = Ledger::default();
    assert!(ledger.reserve(job(1), &[vm(309, "unknown")], 10).is_err());
}

#[test]
fn destruction_requires_ledger_range_pool_and_exact_identity() {
    let row = Ledger::default().reserve(job(1), &[], 0).unwrap();
    let mut candidate = vm(308, &row.name);
    assert!(row.guard(&candidate).is_ok());
    candidate.pool = "another-pool".into();
    assert!(row.guard(&candidate).is_err());
    candidate.pool = "carrick-ci".into();
    candidate.name = "reused-id".into();
    assert!(row.guard(&candidate).is_err());
    candidate.name = row.name.clone();
    candidate.id = 105;
    assert!(row.guard(&candidate).is_err());
    candidate.id = 308;
    candidate.template = true;
    assert!(row.guard(&candidate).is_err());
}

#[test]
fn exact_labels_reject_extra_missing_and_duplicate_labels() {
    assert!(eligible_labels(&[
        "X64",
        "Linux",
        "willow-kvm",
        "self-hosted"
    ]));
    assert!(!eligible_labels(&["X64", "Linux", "willow-kvm"]));
    assert!(!eligible_labels(&[
        "X64",
        "Linux",
        "willow-kvm",
        "self-hosted",
        "extra"
    ]));
    assert!(!eligible_labels(&[
        "X64",
        "Linux",
        "willow-kvm",
        "willow-kvm"
    ]));
}

#[test]
fn cpu_admission_rejects_eighty_five_percent_and_missing_headroom() {
    assert!(admit_resources(0.724, 16, 11 << 30));
    assert!(!admit_resources(0.725, 16, 11 << 30));
    assert!(!admit_resources(0.75, 16, 11 << 30));
    assert!(!admit_resources(f64::NAN, 16, 11 << 30));
    assert!(!admit_resources(0.1, 0, 11 << 30));
    assert!(!admit_resources(0.1, 16, 9 << 30));
}

#[test]
fn unassigned_reap_deadline_preserves_busy_and_unknown_assignment() {
    let row = Ledger::default().reserve(job(1), &[], 100).unwrap();
    assert_eq!(reap_decision(&row, 999, Assignment::Unassigned), Reap::Keep);
    assert_eq!(
        reap_decision(&row, 1000, Assignment::Unassigned),
        Reap::Destroy
    );
    assert_eq!(reap_decision(&row, 10000, Assignment::Busy), Reap::Keep);
    assert_eq!(reap_decision(&row, 10000, Assignment::Unknown), Reap::Keep);
    assert_eq!(
        reap_decision(&row, 101, Assignment::Completed),
        Reap::Destroy
    );
}

struct MockApi {
    stopped: Vec<u16>,
    destroyed: Vec<u16>,
}
impl ReaperApi for MockApi {
    fn stop(&mut self, id: CloneId) -> Result<(), ScalerError> {
        self.stopped.push(id.get());
        Ok(())
    }
    fn destroy(&mut self, id: CloneId) -> Result<(), ScalerError> {
        self.destroyed.push(id.get());
        Ok(())
    }
}

#[test]
fn mock_api_receives_no_mutations_on_guard_failure_and_reaps_owned_clone() {
    let row = Ledger::default().reserve(job(1), &[], 0).unwrap();
    let mut api = MockApi {
        stopped: vec![],
        destroyed: vec![],
    };
    assert!(reap_owned(&row, &vm(308, "unknown"), &mut api).is_err());
    assert!(api.stopped.is_empty() && api.destroyed.is_empty());
    reap_owned(&row, &vm(308, &row.name), &mut api).unwrap();
    assert_eq!(api.stopped, [308]);
    assert_eq!(api.destroyed, [308]);
}

#[test]
fn completed_job_remains_deduplicated_after_cleanup_and_restart() {
    let mut ledger = Ledger::default();
    ledger.reserve(job(1), &[], 10).unwrap();
    ledger.rows[0].state = State::Destroyed;
    let mut ledger: Ledger = serde_json::from_slice(&serde_json::to_vec(&ledger).unwrap()).unwrap();
    assert!(ledger.reserve(job(1), &[], 20).is_err());
    assert!(ledger.reserve(job(2), &[], 20).is_ok());
}
