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
    let row = ledger.reserve(job(20), &[], 100, Concurrency::ONE).unwrap();
    assert_eq!(row.vm.get(), 308);
    assert!(ledger.reserve(job(20), &[], 101, Concurrency::ONE).is_err());
    assert!(ledger.reserve(job(21), &[], 101, Concurrency::ONE).is_err());
    let saved = serde_json::to_vec(&ledger).unwrap();
    let restored: Ledger = serde_json::from_slice(&saved).unwrap();
    assert_eq!(restored.rows.len(), 1);
    assert_eq!(restored.rows[0].state, State::Reserved);
}

#[test]
fn existing_unknown_clone_blocks_admission_even_without_ledger_entry() {
    let mut ledger = Ledger::default();
    let unknown = PoolMember {
        id: 309,
        pool: POOL.into(),
        template: false,
    };
    assert!(
        ledger
            .reserve(job(1), &[unknown], 10, Concurrency::ONE)
            .is_err()
    );
}

#[test]
fn destruction_requires_ledger_range_pool_and_exact_identity() {
    let row = Ledger::default()
        .reserve(job(1), &[], 0, Concurrency::ONE)
        .unwrap();
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
fn cpu_admission_enforces_director_eighty_percent_ceiling_and_headroom() {
    assert!(admit_resources(0.675, 16, 11 << 30));
    assert!(!admit_resources(0.676, 16, 11 << 30));
    assert!(!admit_resources(0.725, 16, 11 << 30));
    assert!(!admit_resources(0.75, 16, 11 << 30));
    assert!(!admit_resources(f64::NAN, 16, 11 << 30));
    assert!(!admit_resources(0.1, 0, 11 << 30));
    assert!(!admit_resources(0.1, 16, 9 << 30));
}

#[test]
fn serial_host_template_cpu_admission_uses_same_eighty_percent_ceiling() {
    let source = include_str!("../../../scripts/ci/build-template-debian.sh");
    let policy = source
        .lines()
        .find_map(|line| {
            line.strip_prefix("awk -v projected=\"$busy\" '")?
                .strip_suffix('\'')
        })
        .unwrap();
    for (projected, expected) in [
        ("0.79", true),
        ("0.80", true),
        ("0.801", false),
        ("0.84", false),
    ] {
        let status = std::process::Command::new("awk")
            .args(["-v", &format!("projected={projected}"), policy])
            .stdout(std::process::Stdio::null())
            .status()
            .unwrap();
        assert_eq!(status.success(), expected, "projected={projected}");
    }
}

#[test]
fn cached_template_flag_cannot_exempt_a_clone_id_from_the_budget() {
    let member = PoolMember {
        id: 308,
        pool: POOL.into(),
        template: true,
    };
    assert!(
        Ledger::default()
            .reserve(job(1), &[member], 10, Concurrency::ONE)
            .is_err()
    );
}

#[test]
fn unassigned_reap_deadline_preserves_busy_and_unknown_assignment() {
    let row = Ledger::default()
        .reserve(job(1), &[], 100, Concurrency::ONE)
        .unwrap();
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
    let row = Ledger::default()
        .reserve(job(1), &[], 0, Concurrency::ONE)
        .unwrap();
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
    ledger.reserve(job(1), &[], 10, Concurrency::ONE).unwrap();
    ledger.rows[0].state = State::Destroyed;
    ledger.rows[0].assigned = Some(JobId(1));
    let mut ledger: Ledger = serde_json::from_slice(&serde_json::to_vec(&ledger).unwrap()).unwrap();
    assert!(ledger.reserve(job(1), &[], 20, Concurrency::ONE).is_err());
    assert!(ledger.reserve(job(2), &[], 20, Concurrency::ONE).is_ok());
}

#[test]
fn a_job_whose_clone_closed_without_running_it_is_served_again_up_to_a_cap() {
    let mut ledger = Ledger::default();
    for serve in 0..MAX_SERVES_PER_JOB {
        let row = ledger
            .reserve(job(1), &[], 10 + serve as u64, Concurrency::ONE)
            .unwrap();
        // Still active: never served twice at once.
        assert!(ledger.served(job(1)));
        let last = ledger.rows.len() - 1;
        ledger.rows[last].state = State::Destroyed;
        // Never assigned (failed launch, drained, killed): not consumed.
        assert_eq!(ledger.rows[last].name, row.name);
    }
    assert!(ledger.served(job(1)), "cap reached");
    assert!(ledger.reserve(job(1), &[], 99, Concurrency::ONE).is_err());
}

#[test]
fn a_clone_github_diverted_to_another_job_neither_holds_nor_consumes_its_reservation() {
    // Issue #333: a clone minted for run A was assigned job B by GitHub.
    let a = job(1);
    let b = JobKey {
        run: RunId(20),
        attempt: 1,
        job: JobId(21),
    };
    let mut ledger = Ledger::default();
    for serve in 0..=MAX_SERVES_PER_JOB {
        ledger
            .reserve(a, &[], 10 + serve as u64, Concurrency::try_from(2).unwrap())
            .unwrap();
        let last = ledger.rows.len() - 1;
        ledger.rows[last].assigned = Some(JobId(21 + serve as u64));
        // B is running (or was refused) on this clone: never served again.
        assert!(ledger.served(JobKey {
            job: JobId(21 + serve as u64),
            ..b
        }));
        // A is still queued demand: the diverted clone does not hold it ...
        assert!(!ledger.served(a), "serve {serve}: diverted clone held A");
        ledger.rows[last].state = State::Destroyed;
    }
    // ... and diversions never exhaust A's re-serve budget.
    assert!(!ledger.served(a));
    assert!(ledger.reserve(a, &[], 99, Concurrency::ONE).is_ok());
}

#[test]
fn persisted_reaping_resumes_after_runner_removal_or_vm_stop() {
    for stopped in [false, true] {
        let mut ledger = Ledger::default();
        let mut row = ledger.reserve(job(1), &[], 0, Concurrency::ONE).unwrap();
        row.state = State::Reaping;
        row.runner = Some(RunnerId(30));
        row.assigned = None;
        row.task = stopped.then(|| "stop-task".into());
        ledger.rows[0] = row;
        let restored: Ledger =
            serde_json::from_slice(&serde_json::to_vec(&ledger).unwrap()).unwrap();
        let row = &restored.rows[0];
        // The registration disappeared before interruption. Neither a missing
        // assignment nor a misleading live/busy response revokes licensed reap.
        for assignment in [
            Assignment::Unknown,
            Assignment::Busy,
            Assignment::Unassigned,
        ] {
            assert_eq!(
                reap_decision(row, 1, assignment),
                Reap::Destroy,
                "stopped={stopped}"
            );
        }
    }
}

#[test]
fn persisted_reaping_finishes_absence_without_a_recorded_delete_task() {
    let mut row = Ledger::default()
        .reserve(job(1), &[], 0, Concurrency::ONE)
        .unwrap();
    row.state = State::Reaping;
    assert_eq!(
        recovery_decision(&row, false, TaskState::Absent, 1),
        Recovery::FinishAbsent
    );
}

#[test]
fn recovery_distinguishes_failed_absent_clone_from_ambiguous_submission() {
    let mut row = Ledger::default()
        .reserve(job(1), &[], 0, Concurrency::ONE)
        .unwrap();
    assert_eq!(
        recovery_decision(&row, false, TaskState::Absent, 900),
        Recovery::FinishAbsent
    );
    row.state = State::Cloning;
    assert_eq!(
        recovery_decision(&row, false, TaskState::Absent, 900),
        Recovery::Quarantine
    );
    assert_eq!(
        recovery_decision(&row, false, TaskState::Failed, 1),
        Recovery::FinishAbsent
    );
    assert_eq!(
        recovery_decision(&row, false, TaskState::Running, 900),
        Recovery::Wait
    );
    assert_eq!(
        recovery_decision(&row, true, TaskState::Failed, 1),
        Recovery::Inspect
    );
    row.state = State::Reaping;
    assert_eq!(
        recovery_decision(&row, false, TaskState::Succeeded, 1),
        Recovery::FinishAbsent
    );
}

#[test]
fn successful_owned_clone_is_resumed_in_place_without_another_reservation() {
    let mut ledger = Ledger::default();
    let mut row = ledger.reserve(job(1), &[], 0, Concurrency::ONE).unwrap();
    row.state = State::Cloning;
    assert_eq!(
        recovery_decision(&row, true, TaskState::Succeeded, 10),
        Recovery::ResumeClone
    );
    assert_eq!(
        recovery_decision(&row, true, TaskState::Running, 10),
        Recovery::Wait
    );
    assert!(ledger.reserve(job(2), &[], 10, Concurrency::ONE).is_err());
    assert_eq!(ledger.rows.len(), 1);
}

#[test]
fn pilot_job_start_rejects_wrong_repository_event_ref_and_sha() {
    let sha = "a".repeat(40);
    let pilot = Admission::pilot(&sha).unwrap();
    let mut context = JobContext {
        repository: "carrick-sh/carrick".into(),
        event: "workflow_dispatch".into(),
        workflow_ref:
            "carrick-sh/carrick/.github/workflows/willow-pilot.yml@refs/heads/work/willow-pilot"
                .into(),
        git_ref: "refs/heads/work/willow-pilot".into(),
        sha: sha.clone(),
        run_id: 1,
        run_attempt: 1,
    };
    assert!(pilot.authorize(&context).is_ok());
    assert!(
        Admission::pilot(&"b".repeat(40))
            .unwrap()
            .authorize(&context)
            .is_err()
    );
    // The pilot is not a standing policy and vice versa.
    assert!(Admission::Standing.authorize(&context).is_err());
    context.event = "pull_request".into();
    assert!(pilot.authorize(&context).is_err());
    context.event = "workflow_dispatch".into();
    context.repository = "fork/carrick".into();
    assert!(pilot.authorize(&context).is_err());
    context.repository = "carrick-sh/carrick".into();
    context.workflow_ref = "carrick-sh/carrick/.github/workflows/other.yml@refs/heads/main".into();
    assert!(pilot.authorize(&context).is_err());
}

fn standing_context(event: &str, git_ref: &str) -> JobContext {
    JobContext {
        repository: REPOSITORY.into(),
        event: event.into(),
        workflow_ref: format!("{REPOSITORY}/{KERNEL_RUNTIME_WORKFLOW}@{git_ref}"),
        git_ref: git_ref.into(),
        sha: "c".repeat(40),
        run_id: 77,
        run_attempt: 2,
    }
}

fn bound() -> JobPolicy {
    JobPolicy::Bound(RunBinding {
        run: RunId(77),
        attempt: 2,
        sha: "c".repeat(40),
    })
}

#[test]
fn bound_hook_admits_only_the_vetted_run_attempt_and_sha() {
    let push = standing_context("push", "refs/heads/main");
    assert!(bound().authorize(&push).is_ok());
    let mut other = standing_context("push", "refs/heads/main");
    other.run_id = 78;
    assert!(bound().authorize(&other).is_err(), "another run");
    let mut other = standing_context("push", "refs/heads/main");
    other.run_attempt = 3;
    assert!(bound().authorize(&other).is_err(), "another attempt");
    let mut other = standing_context("push", "refs/heads/main");
    other.sha = "d".repeat(40);
    assert!(bound().authorize(&other).is_err(), "another SHA");
    // The binding never widens the standing policy.
    assert!(
        bound()
            .authorize(&standing_context("pull_request", "refs/heads/main"))
            .is_err()
    );
    let mut foreign = standing_context("push", "refs/heads/main");
    foreign.workflow_ref = format!("{REPOSITORY}/.github/workflows/ci.yml@refs/heads/main");
    assert!(bound().authorize(&foreign).is_err());
}

#[test]
fn standing_job_start_admits_push_and_dispatch_on_main_only() {
    let queue = "refs/heads/gh-readonly-queue/main/pr-42-0123456789abcdef0123456789abcdef01234567";
    for (event, git_ref) in [
        ("push", "refs/heads/main"),
        ("workflow_dispatch", "refs/heads/main"),
    ] {
        assert!(
            Admission::Standing
                .authorize(&standing_context(event, git_ref))
                .is_ok(),
            "{event} {git_ref}"
        );
    }
    for (event, git_ref) in [
        ("merge_group", queue),
        // Untrusted pull-request code never reaches a self-hosted runner.
        ("pull_request", "refs/pull/42/merge"),
        ("pull_request", "refs/heads/main"),
        ("pull_request_target", "refs/heads/main"),
        ("schedule", "refs/heads/main"),
        ("push", "refs/heads/work/feature"),
        ("workflow_dispatch", "refs/heads/work/feature"),
        ("merge_group", "refs/heads/gh-readonly-queue/other/pr-1-abc"),
        ("merge_group", "refs/heads/gh-readonly-queue/main/"),
        ("merge_group", "refs/heads/main"),
        ("push", "refs/tags/v1"),
    ] {
        assert!(
            Admission::Standing
                .authorize(&standing_context(event, git_ref))
                .is_err(),
            "{event} {git_ref} must be rejected"
        );
    }
}

#[test]
fn standing_job_start_rejects_a_foreign_workflow_repository_or_sha() {
    let mut context = standing_context("push", "refs/heads/main");
    context.workflow_ref = format!("{REPOSITORY}/.github/workflows/ci.yml@refs/heads/main");
    assert!(Admission::Standing.authorize(&context).is_err());
    context.workflow_ref = format!("{REPOSITORY}/{PILOT_WORKFLOW}@refs/heads/main");
    assert!(Admission::Standing.authorize(&context).is_err());
    // The workflow file must be read at the very ref being run.
    context.workflow_ref = format!("{REPOSITORY}/{KERNEL_RUNTIME_WORKFLOW}@refs/heads/other");
    assert!(Admission::Standing.authorize(&context).is_err());
    let mut context = standing_context("push", "refs/heads/main");
    context.repository = "fork/carrick".into();
    assert!(Admission::Standing.authorize(&context).is_err());
    let mut context = standing_context("push", "refs/heads/main");
    context.workflow_ref = format!("fork/carrick/{KERNEL_RUNTIME_WORKFLOW}@refs/heads/main");
    assert!(Admission::Standing.authorize(&context).is_err());
    let mut context = standing_context("push", "refs/heads/main");
    context.sha = "short".into();
    assert!(Admission::Standing.authorize(&context).is_err());
}

fn standing_run(event: &str, branch: &str) -> serde_json::Value {
    serde_json::json!({
        "event": event,
        "head_branch": branch,
        "head_sha": "d".repeat(40),
        "path": KERNEL_RUNTIME_WORKFLOW,
        "repository": {"full_name": REPOSITORY},
        "head_repository": {"full_name": REPOSITORY},
    })
}

#[test]
fn standing_demand_serves_only_trusted_kernel_runtime_runs() {
    for (event, branch) in [("push", "main"), ("workflow_dispatch", "main")] {
        assert!(Admission::Standing.admits_run(&standing_run(event, branch)));
    }
    for (event, branch) in [
        ("pull_request", "main"),
        ("pull_request", "work/x"),
        ("schedule", "main"),
        (
            "merge_group",
            "gh-readonly-queue/main/pr-7-0123456789abcdef",
        ),
        ("push", "work/x"),
    ] {
        assert!(!Admission::Standing.admits_run(&standing_run(event, branch)));
    }
    let mut foreign = standing_run("push", "main");
    foreign["path"] = ".github/workflows/ci.yml".into();
    assert!(!Admission::Standing.admits_run(&foreign));
    let mut fork = standing_run("push", "main");
    fork["head_repository"]["full_name"] = "fork/carrick".into();
    assert!(!Admission::Standing.admits_run(&fork));
    // The pilot never serves kernel-runtime demand.
    assert!(
        !Admission::pilot(&"d".repeat(40))
            .unwrap()
            .admits_run(&standing_run("push", "main"))
    );
}

#[test]
fn job_policy_file_round_trips_and_rejects_unknown_text() {
    for policy in [
        bound(),
        JobPolicy::Pilot {
            sha: "e".repeat(40),
        },
    ] {
        assert_eq!(JobPolicy::parse(&policy.render()).unwrap(), policy);
    }
    let sha = "e".repeat(40);
    for text in [
        "".to_owned(),
        "standing".to_owned(),
        "pilot".to_owned(),
        "pilot short".to_owned(),
        format!("standing run=x attempt=1 sha={sha}"),
        format!("standing run=1 attempt=0 sha={sha}"),
        "standing run=1 attempt=1 sha=short".to_owned(),
        format!("standing attempt=1 run=1 sha={sha}"),
    ] {
        assert!(JobPolicy::parse(&text).is_err(), "{text:?}");
    }
}

#[test]
fn serial_host_policy_file_must_be_owner_writable_only() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("policy");
    std::fs::write(&path, format!("{}\n", bound().render())).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let uid = unsafe { libc::geteuid() };
    assert_eq!(read_policy(&path, Some(uid)).unwrap(), bound());
    // Production requires root ownership.
    assert!(read_policy(&path, Some(uid.wrapping_add(1))).is_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o664)).unwrap();
    assert!(read_policy(&path, None).is_err());
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(&path, &link).unwrap();
    assert!(read_policy(&link, None).is_err());
}

#[test]
fn standing_concurrency_is_bounded_at_two_and_unknown_objects_still_block() {
    assert!("0".parse::<Concurrency>().is_err());
    assert!("3".parse::<Concurrency>().is_err());
    let two: Concurrency = "2".parse().unwrap();
    let mut ledger = Ledger::default();
    let first = ledger.reserve(job(1), &[], 10, two).unwrap();
    let member = |id| PoolMember {
        id,
        pool: POOL.into(),
        template: false,
    };
    // The first clone exists in the pool; a second, distinct VMID is chosen.
    let second = ledger
        .reserve(job(2), &[member(first.vm.get())], 11, two)
        .unwrap();
    assert_ne!(first.vm, second.vm);
    assert!(
        ledger
            .reserve(
                job(3),
                &[member(first.vm.get()), member(second.vm.get())],
                12,
                two
            )
            .is_err()
    );
    // One clone budget: the default.
    let mut ledger = Ledger::default();
    ledger.reserve(job(1), &[], 10, Concurrency::ONE).unwrap();
    assert!(ledger.reserve(job(2), &[], 11, two).is_ok());
    // An unknown pool object blocks admission even with spare budget.
    let mut ledger = Ledger::default();
    ledger.reserve(job(1), &[], 10, two).unwrap();
    assert!(ledger.reserve(job(2), &[member(340)], 11, two).is_err());
}

fn runs_on(workflow: &str, job: &str) -> Vec<String> {
    let docs = yaml_rust2::YamlLoader::load_from_str(workflow).unwrap();
    docs[0]["jobs"][job]["runs-on"]
        .as_vec()
        .unwrap()
        .iter()
        .map(|label| label.as_str().unwrap().to_owned())
        .collect()
}

#[test]
fn workflow_runner_labels_are_the_controller_label_constants() {
    let kernel = include_str!("../../../.github/workflows/kernel-runtime.yml");
    let pilot = include_str!("../../../.github/workflows/willow-pilot.yml");
    // `kvm-tests` is the hosted GCP backend; Willow serves the fallback job.
    assert_eq!(runs_on(kernel, "kvm-tests-willow"), LABELS);
    assert_eq!(runs_on(pilot, "kvm"), LABELS);
    assert_eq!(runs_on(kernel, "hvf-kernel"), HVF_LABELS);
    // The closure job never takes the merge-queue runner.
    assert_eq!(runs_on(kernel, "hvf-closure"), HVF_CLOSURE_LABELS);
    assert_ne!(HVF_CLOSURE_LABELS, HVF_LABELS);
}

/// Exactly one KVM backend runs: the two lane jobs' conditions are complements
/// over one selection expression, and the gate and the aggregate read the
/// selected job's result through that same expression.
#[test]
fn kvm_backends_are_mutually_exclusive_and_read_through_one_selection() {
    let kernel = include_str!("../../../.github/workflows/kernel-runtime.yml");
    let docs = yaml_rust2::YamlLoader::load_from_str(kernel).unwrap();
    let jobs = &docs[0]["jobs"];
    let select = "(vars.CARRICK_GCP_KVM == 'true' && vars.CARRICK_KVM_BACKEND != 'willow')";
    let squash = |s: &str| s.split_whitespace().collect::<Vec<_>>().join(" ");
    let gcp = squash(jobs["kvm-tests"]["if"].as_str().unwrap());
    let willow = squash(jobs["kvm-tests-willow"]["if"].as_str().unwrap());
    assert!(gcp.contains(&select[1..select.len() - 1]), "{gcp}");
    assert!(willow.contains(&format!("!{select}")), "{willow}");
    assert!(willow.contains("vars.CARRICK_SELF_HOSTED_KVM == 'true'"));
    assert_eq!(jobs["kvm-tests"]["runs-on"].as_str(), Some("ubuntu-latest"));
    assert_eq!(
        jobs["kvm-tests"]["permissions"]["id-token"].as_str(),
        Some("write")
    );
    let pick = format!("{select} && needs.kvm-tests.result || needs.kvm-tests-willow.result");
    assert!(squash(jobs["kvm-gate"]["if"].as_str().unwrap()).contains(&pick));
    let ok_env = &jobs["trusted-hardware-ok"]["steps"][0]["env"];
    assert!(squash(ok_env["KVM"].as_str().unwrap()).contains(&pick));
    // Both backends publish the one artifact name the gate downloads.
    for lane in ["kvm-tests", "kvm-tests-willow"] {
        let names: Vec<_> = jobs[lane]["steps"]
            .as_vec()
            .unwrap()
            .iter()
            .filter_map(|s| s["with"]["name"].as_str())
            .collect();
        assert!(
            names.contains(&"receipt-kvm-${{ github.sha }}-${{ github.run_attempt }}"),
            "{lane}: {names:?}"
        );
    }
}

#[test]
fn self_hosted_jobs_never_run_on_pull_request_events() {
    let kernel = include_str!("../../../.github/workflows/kernel-runtime.yml");
    let docs = yaml_rust2::YamlLoader::load_from_str(kernel).unwrap();
    let on = docs[0]["on"].as_hash().unwrap();
    for event in on.keys() {
        let event = event.as_str().unwrap();
        assert!(
            ["push", "workflow_dispatch"].contains(&event),
            "kernel-runtime.yml must not trigger on {event}"
        );
    }
    assert_eq!(on.len(), 2);
    assert!(!kernel.contains("merge_group"));
    assert!(!kernel.contains("check-merge-group"));
    assert_eq!(docs[0]["on"]["push"]["branches"][0].as_str(), Some("main"));
}

#[test]
fn one_always_job_requires_both_trusted_hardware_lanes() {
    let kernel = include_str!("../../../.github/workflows/kernel-runtime.yml");
    let docs = yaml_rust2::YamlLoader::load_from_str(kernel).unwrap();
    let ok = &docs[0]["jobs"]["trusted-hardware-ok"];
    assert_eq!(ok["if"].as_str(), Some("${{ always() }}"));
    let needs: Vec<_> = ok["needs"]
        .as_vec()
        .unwrap()
        .iter()
        .map(|n| n.as_str().unwrap())
        .collect();
    for job in [
        "hvf-kernel",
        "kvm-tests",
        "kvm-tests-willow",
        "hvf-gate",
        "kvm-gate",
    ] {
        assert!(needs.contains(&job), "{job}");
    }
    let script = ok["steps"][0]["run"].as_str().unwrap();
    assert!(script.contains("test \"$HVF\" = success"));
    assert!(script.contains("test \"$KVM\" = success"));
    assert!(script.contains("test \"$HVF_GATE\" = success"));
    assert!(script.contains("test \"$KVM_GATE\" = success"));
    // No step interpolates the merge-group base SHA into a shell script.
    for job in docs[0]["jobs"].as_hash().unwrap().values() {
        for step in job["steps"].as_vec().into_iter().flatten() {
            if let Some(run) = step["run"].as_str() {
                assert!(!run.contains("github.event.merge_group"), "{run}");
            }
        }
    }
}

#[test]
fn job_admission_and_quiesce_share_one_durable_exclusion_boundary() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("admission.lock"), "").unwrap();
    assert_eq!(quiesce_guest(dir.path()).unwrap(), Assignment::Unassigned);
    assert!(mark_job_started(dir.path()).is_err());
    std::fs::remove_file(dir.path().join("draining")).unwrap();
    mark_job_started(dir.path()).unwrap();
    assert_eq!(quiesce_guest(dir.path()).unwrap(), Assignment::Busy);
    assert!(!dir.path().join("draining").exists());
}

#[test]
fn durable_ledger_round_trip_rejects_corruption_without_resetting_budget() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.json");
    let mut ledger = Ledger::default();
    ledger.reserve(job(1), &[], 10, Concurrency::ONE).unwrap();
    ledger.save(&path).unwrap();
    let mut restored = Ledger::load(&path).unwrap();
    assert!(restored.reserve(job(2), &[], 11, Concurrency::ONE).is_err());
    std::fs::write(&path, "{broken").unwrap();
    assert!(Ledger::load(&path).is_err());
}

#[test]
fn hardware_lanes_never_wait_and_hosted_gates_compare_parent_main() {
    let kernel = include_str!("../../../.github/workflows/kernel-runtime.yml");
    let docs = yaml_rust2::YamlLoader::load_from_str(kernel).unwrap();
    let jobs = &docs[0]["jobs"];
    let runs = |job: &str| -> Vec<String> {
        jobs[job]["steps"]
            .as_vec()
            .unwrap()
            .iter()
            .filter_map(|s| s["run"].as_str().map(str::to_owned))
            .collect()
    };
    // A lane job waiting on a base receipt would hold the single runner the
    // base entry's job needs (queue deadlock).
    for lane in ["hvf-kernel", "kvm-tests", "kvm-tests-willow"] {
        assert!(
            runs(lane).iter().all(|r| !r.contains("ci-receipt gate")),
            "{lane} must only produce and upload its receipt"
        );
    }
    for (gate, lane, name) in [
        ("hvf-gate", "hvf-kernel", "receipt-hvf-"),
        ("kvm-gate", "kvm-tests", "receipt-kvm-"),
    ] {
        let job = &jobs[gate];
        assert_eq!(job["runs-on"].as_str(), Some("ubuntu-latest"));
        assert_eq!(job["needs"][0].as_str(), Some(lane));
        // Above the 90-minute wait bound, with margin.
        assert!(job["timeout-minutes"].as_i64().unwrap() >= 100);
        let steps = job["steps"].as_vec().unwrap();
        let checkout = steps
            .iter()
            .find(|s| s["uses"].as_str() == Some("actions/checkout@v4"))
            .unwrap();
        assert_eq!(
            checkout["with"]["ref"].as_str(),
            Some("${{ github.sha }}"),
            "{gate} runs the current trusted landed commit"
        );
        assert_eq!(checkout["with"]["fetch-depth"].as_i64(), Some(2));
        assert!(
            job["if"]
                .as_str()
                .unwrap()
                .contains("github.event_name == 'push'")
        );
        let parent = steps
            .iter()
            .find(|s| s["id"].as_str() == Some("parent"))
            .unwrap();
        assert!(
            parent["run"]
                .as_str()
                .unwrap()
                .contains("git rev-parse HEAD^1")
        );
        let comparison = steps
            .iter()
            .find(|s| {
                s["run"]
                    .as_str()
                    .is_some_and(|r| r.contains("ci-receipt gate"))
            })
            .unwrap();
        assert_eq!(
            comparison["env"]["BASE_SHA"].as_str(),
            Some("${{ steps.parent.outputs.sha }}")
        );
        let checkouts = steps
            .iter()
            .filter(|s| {
                s["uses"]
                    .as_str()
                    .is_some_and(|u| u.starts_with("actions/checkout"))
            })
            .count();
        assert_eq!(checkouts, 1);
        let download = steps
            .iter()
            .find(|s| s["uses"].as_str() == Some("actions/download-artifact@v4"))
            .unwrap();
        assert!(
            download["with"]["pattern"]
                .as_str()
                .unwrap()
                .starts_with(name)
        );
        let script = runs(gate).join("\n");
        assert!(script.contains("cargo build --locked --release -p carrick-xtask"));
        assert!(script.contains("--wait-minutes 90"));
        assert!(script.contains("--run-attempt \"$GITHUB_RUN_ATTEMPT\""));
        assert!(
            !script.contains("--manifest-path"),
            "build in the base checkout itself"
        );
    }
}

#[test]
fn template_sets_and_verifies_disk_boot_order_after_attaching_the_disk() {
    let source = include_str!("../../../scripts/ci/build-template-debian.sh");
    let lines: Vec<&str> = source.lines().collect();
    let attach = lines
        .iter()
        .position(|l| l.starts_with("qm set 300 --scsi0 "))
        .unwrap();
    // Combined with the attach, PVE 9 kept `order=net0;ide2` (live failure).
    assert!(!lines[attach].contains("--boot"));
    let boot = lines
        .iter()
        .position(|l| *l == "qm set 300 --boot order=scsi0")
        .unwrap();
    assert!(boot > attach);
    assert!(lines[boot + 1].contains("grep -qx 'boot: order=scsi0'"));
    let start = lines
        .iter()
        .position(|l| l.contains("/status/start"))
        .unwrap();
    assert!(start > boot + 1, "verified before the VM starts");
    // The xtask compatibility guard runs before any VM exists.
    let guard = lines.iter().position(|l| l.contains("glibc_max=")).unwrap();
    let create = lines
        .iter()
        .position(|l| l.starts_with("qm create 300"))
        .unwrap();
    assert!(guard < create);
}

#[test]
fn serial_host_aggregate_requires_push_gates_and_allows_owner_seeding() {
    let kernel = include_str!("../../../.github/workflows/kernel-runtime.yml");
    let docs = yaml_rust2::YamlLoader::load_from_str(kernel).unwrap();
    let script = docs[0]["jobs"]["trusted-hardware-ok"]["steps"][0]["run"]
        .as_str()
        .unwrap();
    for (event, hvf, kvm, hvf_gate, kvm_gate, expected) in [
        ("push", "success", "success", "success", "success", true),
        ("push", "success", "success", "failure", "success", false),
        ("push", "success", "success", "success", "failure", false),
        ("push", "success", "success", "skipped", "skipped", false),
        ("push", "skipped", "success", "success", "success", false),
        ("push", "success", "cancelled", "success", "success", false),
        (
            "workflow_dispatch",
            "success",
            "success",
            "skipped",
            "skipped",
            true,
        ),
        (
            "workflow_dispatch",
            "failure",
            "success",
            "skipped",
            "skipped",
            false,
        ),
    ] {
        let output = std::process::Command::new("bash")
            .args(["-e", "-c", script])
            .env("EVENT", event)
            .env("HVF", hvf)
            .env("KVM", kvm)
            .env("HVF_GATE", hvf_gate)
            .env("KVM_GATE", kvm_gate)
            .env("KVM_BACKEND", "willow")
            .output()
            .unwrap();
        assert_eq!(
            output.status.success(),
            expected,
            "{event}: hvf={hvf} kvm={kvm} hvf-gate={hvf_gate} kvm-gate={kvm_gate}"
        );
    }
}
