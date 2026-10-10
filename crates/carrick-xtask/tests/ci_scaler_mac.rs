#![allow(clippy::unwrap_used, clippy::expect_used)]
use carrick_xtask::ci_scaler::*;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

fn job(id: u64) -> JobKey {
    JobKey {
        run: RunId(10),
        attempt: 1,
        job: JobId(id),
    }
}

#[test]
fn mac_ledger_serves_one_runner_and_each_job_attempt_once() {
    let mut ledger = MacLedger::default();
    let mut row = ledger.reserve(job(1), 100).unwrap();
    assert_eq!(row.name, "carrick-hvf-10-1-1-100");
    assert_eq!(row.state, MacState::Registering);
    assert!(ledger.reserve(job(2), 101).is_err(), "one runner at a time");
    row.state = MacState::Done;
    ledger.rows[0] = row;
    assert!(ledger.reserve(job(1), 102).is_err(), "job key deduplicated");
    let restored: MacLedger =
        serde_json::from_slice(&serde_json::to_vec(&ledger).unwrap()).unwrap();
    let mut restored = restored;
    assert!(restored.reserve(job(2), 103).is_ok());
}

fn launched(created: u64) -> MacRecord {
    let mut row = MacLedger::default().reserve(job(1), created).unwrap();
    row.state = MacState::Launched;
    row.runner = Some(RunnerId(7));
    row
}

#[test]
fn mac_step_never_removes_a_busy_runner_and_drains_only_after_the_deadline() {
    let row = launched(1000);
    for done in [false, true] {
        assert_eq!(
            mac_step(&row, Assignment::Busy, done, 99_999),
            MacStep::Wait
        );
    }
    assert_eq!(
        mac_step(&row, Assignment::Unassigned, false, 1000 + 899),
        MacStep::Wait
    );
    assert_eq!(
        mac_step(&row, Assignment::Unassigned, false, 1000 + 900),
        MacStep::Drain
    );
    // Runner process gone without a job: rejected and killed, or failed.
    assert_eq!(
        mac_step(&row, Assignment::Unassigned, true, 1001),
        MacStep::Remove
    );
    // Completed: let the ephemeral runner exit before removing it.
    assert_eq!(
        mac_step(&row, Assignment::Completed, false, 1001),
        MacStep::Wait
    );
    assert_eq!(
        mac_step(&row, Assignment::Completed, true, 1001),
        MacStep::Remove
    );
    assert_eq!(
        mac_step(&row, Assignment::Unknown, false, 99_999),
        MacStep::Wait
    );
    let mut interrupted = row.clone();
    interrupted.state = MacState::Registering;
    assert_eq!(
        mac_step(&interrupted, Assignment::Unknown, true, 1001),
        MacStep::Remove
    );
    let mut draining = row;
    draining.state = MacState::Draining;
    assert_eq!(
        mac_step(&draining, Assignment::Unassigned, false, 1001),
        MacStep::Drain
    );
}

#[test]
fn mac_target_rejects_option_and_shell_injection() {
    let ok = |host: &str, xtask: &str, root: &str| {
        MacTarget::new(host.into(), xtask.into(), root.into()).is_ok()
    };
    assert!(ok(
        "rentamac@cloudmac",
        "/Volumes/carrick-build/carrick-ci/bin/carrick-xtask",
        "/Volumes/carrick-build/carrick-ci/run"
    ));
    assert!(!ok("-oProxyCommand=x", "/a/b", "/a/c"));
    assert!(!ok("host;rm", "/a/b", "/a/c"));
    assert!(!ok("host", "relative/xtask", "/a/c"));
    assert!(!ok("host", "/a/b c", "/a/c"));
    assert!(!ok("host", "/a/../b", "/a/c"));
    assert!(!ok("host", "/a/b", "/a/$(id)"));
}

/// A root-owned, not group/other-writable executable present on macOS and Linux.
const ROOT_OWNED_EXE: &str = "/bin/kill";

#[test]
fn run_once_state_is_one_use_and_standing_policy_bound() {
    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let uid = unsafe { libc::geteuid() };
    let name = "carrick-hvf-10-1-1-100";
    let state = prepare_run_once(name, Path::new(ROOT_OWNED_EXE), root.path(), uid).unwrap();
    assert_eq!(
        read_policy(&state.join("policy")).unwrap(),
        Admission::Standing
    );
    assert!(state.join("admission.lock").is_file());
    let hook = std::fs::read_to_string(state.join("admit-job.sh")).unwrap();
    assert!(hook.contains("ci-scaler admit-job --policy-file"));
    assert!(hook.contains("exec /bin/kill -KILL 0"));
    assert!(!hook.contains("/usr/local/bin/carrick-xtask"));
    // Replaying a name loses at mkdir.
    assert!(prepare_run_once(name, Path::new(ROOT_OWNED_EXE), root.path(), uid).is_err());
    // Only mac-jit names; never a path.
    for bad in [
        "../etc",
        "carrick-hvf-",
        "carrick-hvf-1/2",
        "carrick-ci-1-1-1-1",
    ] {
        assert!(
            prepare_run_once(bad, Path::new(ROOT_OWNED_EXE), root.path(), uid).is_err(),
            "{bad}"
        );
    }
}

#[test]
fn run_once_refuses_a_job_writable_hook_binary_or_state_root() {
    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let uid = unsafe { libc::geteuid() };
    // An executable the runner user owns could be replaced by a job.
    let own = root.path().join("xtask");
    std::fs::write(&own, "#!/bin/sh\n").unwrap();
    std::fs::set_permissions(&own, std::fs::Permissions::from_mode(0o755)).unwrap();
    if uid != 0 {
        assert!(prepare_run_once("carrick-hvf-1-1-1-1", &own, root.path(), uid).is_err());
    }
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
    assert!(
        prepare_run_once(
            "carrick-hvf-1-1-1-2",
            Path::new(ROOT_OWNED_EXE),
            root.path(),
            uid
        )
        .is_err()
    );
}
