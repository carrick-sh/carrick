#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;
use std::process::Command;

use carrick_xtask::cli::{self, CliError, RepoInfo};
use carrick_xtask::command::{self, CommandError};

fn init_git_repo(dir: &Path) {
    let output = Command::new("git")
        .args(["init"])
        .current_dir(dir)
        .output()
        .expect("git init");
    assert!(output.status.success(), "git init failed: {:?}", output);

    let _ = Command::new("git")
        .args(["config", "user.name", "Carrick Test"])
        .current_dir(dir)
        .output();
    let _ = Command::new("git")
        .args(["config", "user.email", "test@carrick.sh"])
        .current_dir(dir)
        .output();

    let output = Command::new("git")
        .args(["commit", "--allow-empty", "-m", "initial commit"])
        .current_dir(dir)
        .output()
        .expect("git commit");
    assert!(output.status.success(), "git commit failed: {:?}", output);
}

fn add_worktree(repo: &Path, wt: &Path, branch: &str) {
    let output = Command::new("git")
        .args(["worktree", "add", wt.to_str().unwrap(), "-b", branch])
        .current_dir(repo)
        .output()
        .expect("git worktree add");
    assert!(
        output.status.success(),
        "git worktree add failed: {:?}",
        output
    );
}

fn get_head(repo: &Path) -> String {
    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(repo)
        .output()
        .expect("git rev-parse HEAD");
    assert!(
        output.status.success(),
        "git rev-parse HEAD failed: {:?}",
        output
    );
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

#[test]
fn info_resolves_linked_worktree() {
    let temp = tempfile::tempdir().unwrap();
    let main_repo = temp.path().join("main_repo");
    std::fs::create_dir_all(&main_repo).unwrap();
    init_git_repo(&main_repo);

    let wt = temp.path().join("linked_wt");
    add_worktree(&main_repo, &wt, "branch-wt");
    let expected_head = get_head(&wt);
    let canonical_wt = std::fs::canonicalize(&wt).unwrap();

    let bin = env!("CARGO_BIN_EXE_carrick-xtask");

    // Test with explicit --root
    let output = Command::new(bin)
        .args(["--root", wt.to_str().unwrap(), "info"])
        .output()
        .expect("spawn carrick-xtask");
    assert!(
        output.status.success(),
        "carrick-xtask failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let info: RepoInfo = serde_json::from_str(&String::from_utf8_lossy(&output.stdout)).unwrap();
    assert_eq!(info.schema_version, 1);
    assert_eq!(info.repository_root, canonical_wt);
    assert_eq!(info.head, expected_head);

    // Test with cwd inside linked worktree (default root)
    let output_cwd = Command::new(bin)
        .arg("info")
        .current_dir(&wt)
        .output()
        .expect("spawn carrick-xtask with cwd");
    assert!(
        output_cwd.status.success(),
        "carrick-xtask with cwd failed: {}",
        String::from_utf8_lossy(&output_cwd.stderr)
    );
    let info_cwd: RepoInfo =
        serde_json::from_str(&String::from_utf8_lossy(&output_cwd.stdout)).unwrap();
    assert_eq!(info_cwd.schema_version, 1);
    assert_eq!(info_cwd.repository_root, canonical_wt);
    assert_eq!(info_cwd.head, expected_head);
}

#[test]
fn info_handles_space_in_root() {
    let temp = tempfile::tempdir().unwrap();
    let spaced_repo = temp.path().join("repo with spaces");
    std::fs::create_dir_all(&spaced_repo).unwrap();
    init_git_repo(&spaced_repo);

    let expected_head = get_head(&spaced_repo);
    let canonical_spaced = std::fs::canonicalize(&spaced_repo).unwrap();

    let bin = env!("CARGO_BIN_EXE_carrick-xtask");

    let output = Command::new(bin)
        .args(["--root", spaced_repo.to_str().unwrap(), "info"])
        .output()
        .expect("spawn carrick-xtask");
    assert!(
        output.status.success(),
        "carrick-xtask failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let info: RepoInfo = serde_json::from_str(&String::from_utf8_lossy(&output.stdout)).unwrap();
    assert_eq!(info.schema_version, 1);
    assert_eq!(info.repository_root, canonical_spaced);
    assert_eq!(info.head, expected_head);
}

#[test]
fn invalid_root_fails() {
    let temp = tempfile::tempdir().unwrap();
    let non_repo = temp.path().join("not_a_repo");
    std::fs::create_dir_all(&non_repo).unwrap();

    let bin = env!("CARGO_BIN_EXE_carrick-xtask");

    // Subprocess execution test
    let output = Command::new(bin)
        .args(["--root", non_repo.to_str().unwrap(), "info"])
        .output()
        .expect("spawn carrick-xtask");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("invalid git repository") || stderr.contains("not a git repository"),
        "unexpected stderr: {stderr}"
    );

    // Typed Result test on cli::run
    let res = cli::run([
        "carrick-xtask",
        "--root",
        non_repo.to_str().unwrap(),
        "info",
    ]);
    match res {
        Err(CliError::InvalidRepository { .. }) => {}
        other => panic!("expected InvalidRepository error, got {other:?}"),
    }
}

#[test]
fn unknown_command_fails() {
    let bin = env!("CARGO_BIN_EXE_carrick-xtask");

    // Subprocess execution test
    let output = Command::new(bin)
        .arg("unknown-command")
        .output()
        .expect("spawn carrick-xtask");
    assert!(!output.status.success());

    // Typed Result test on cli::run
    let res = cli::run(["carrick-xtask", "unknown-command"]);
    match res {
        Err(CliError::Clap(..)) => {}
        other => panic!("expected Clap error, got {other:?}"),
    }
}

#[test]
fn checked_command_preserves_failure_status_and_stderr() {
    let res = command::run_checked(
        "git",
        ["rev-parse", "--verify", "nonexistent_ref_12345"],
        None,
    );
    match res {
        Err(CommandError::NonZeroExit { status, stderr, .. }) => {
            assert!(!status.success());
            assert!(
                stderr.contains("fatal:"),
                "expected 'fatal:' in stderr, got: {stderr}"
            );
        }
        other => panic!("expected NonZeroExit, got {other:?}"),
    }
}

#[test]
fn remote_accept_cli_help() {
    let bin = env!("CARGO_BIN_EXE_carrick-xtask");
    let output = Command::new(bin)
        .args(["remote-accept", "--help"])
        .output()
        .expect("spawn carrick-xtask remote-accept --help");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(combined.contains("--ref"));
    assert!(combined.contains("--phase"));
    assert!(combined.contains("--host"));
    assert!(combined.contains("--remote-root"));
    assert!(combined.contains("--attach"));
    assert!(!combined.contains("--keep-worktree"));
}

fn worktree_command_status(script: &str, leased: bool) -> std::process::ExitStatus {
    let repo = tempfile::tempdir().unwrap();
    init_git_repo(repo.path());
    let lock = tempfile::NamedTempFile::new().unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_carrick-xtask"));
    command
        .arg("--root")
        .arg(repo.path())
        .args(["worktree-run", "--"]);
    if leased {
        command
            .arg(env!("CARGO_BIN_EXE_carrick-xtask"))
            .args(["host-lease", "--mode", "gate", "--"])
            .env("CARRICK_HOST_LEASE_PATH", lock.path())
            .env_remove("CARRICK_HOST_LEASE_SOCKET")
            .env_remove("CARRICK_HOST_LEASE_FD");
    }
    command.args(["/bin/sh", "-c", script]).status().unwrap()
}

#[test]
fn worktree_run_preserves_exit_code() {
    for leased in [false, true] {
        assert_eq!(worktree_command_status("exit 37", leased).code(), Some(37));
    }
}

#[test]
fn worktree_run_preserves_signal_status() {
    for leased in [false, true] {
        let status = worktree_command_status("kill -TERM $$", leased);
        assert_eq!(
            carrick_xtask::host_lease::extract_exit_code(&status),
            128 + libc::SIGTERM
        );
        if leased {
            assert_eq!(status.code(), Some(128 + libc::SIGTERM));
        } else {
            use std::os::unix::process::ExitStatusExt;
            assert_eq!(status.signal(), Some(libc::SIGTERM));
        }
    }
}

#[test]
fn worktree_run_keeps_build_settings_without_package_metadata() {
    let repo = tempfile::tempdir().unwrap();
    init_git_repo(repo.path());
    let output = Command::new(env!("CARGO_BIN_EXE_carrick-xtask"))
        .arg("--root")
        .arg(repo.path())
        .args([
            "worktree-run",
            "--",
            "/bin/sh",
            "-c",
            r#"printf '%s\n' "${CARGO_MANIFEST_DIR-unset}" "${CARGO_PKG_NAME-unset}" "${CARGO_PKG_VERSION-unset}" "$CARGO_BUILD_JOBS" "$CARGO_TARGET_DIR""#,
        ])
        .env("CARGO_MANIFEST_DIR", "/outer/package")
        .env("CARGO_PKG_NAME", "outer-package")
        .env("CARGO_PKG_VERSION", "9.9.9")
        .env("CARGO_BUILD_JOBS", "2")
        .env("CARGO_TARGET_DIR", "retained-target")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "unset\nunset\nunset\n2\nretained-target\n"
    );
}

#[test]
fn subcommand_help_exits_zero_on_stdout() {
    let bin = env!("CARGO_BIN_EXE_carrick-xtask");
    let output = Command::new(bin)
        .args(["ci-scaler", "admit-job", "--help"])
        .output()
        .expect("spawn carrick-xtask ci-scaler admit-job --help");
    assert!(output.status.success(), "help exited {:?}", output.status);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--controller"), "stdout: {stdout}");
    assert!(output.stderr.is_empty());

    let mut out = Vec::new();
    cli::run_with_writer(["carrick-xtask", "remote-accept", "--help"], &mut out)
        .expect("help is not an error");
    assert!(String::from_utf8_lossy(&out).contains("--ref"));
}

#[test]
fn lint_source_reports_later_checks_after_a_ratchet_failure() {
    // Exercise the real entry points against a complete source fixture, without
    // compiling a second xtask or changing the developer's checkout or env.
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let fixture = tempfile::tempdir().unwrap();
    let files = command::run_checked("git", ["ls-files", "-z"], Some(&root)).unwrap();
    for relative in files.stdout.split('\0').filter(|path| !path.is_empty()) {
        let source = root.join(relative);
        let target = fixture.path().join(relative);
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        if source.symlink_metadata().unwrap().file_type().is_symlink() {
            std::os::unix::fs::symlink(std::fs::read_link(source).unwrap(), target).unwrap();
        } else {
            std::fs::copy(source, target).unwrap();
        }
    }
    init_git_repo(fixture.path());
    let policy_path = fixture
        .path()
        .join("scripts/terminal-custody-ceilings.json");
    std::fs::write(&policy_path, "invalid JSON").unwrap();

    let failed = Command::new(env!("CARGO_BIN_EXE_carrick-xtask"))
        .arg("--root")
        .arg(fixture.path())
        .arg("lint-source")
        .env_remove("CARRICK_AUTHORITY_BASE")
        .env_remove("CARRICK_PROBE_COVERAGE_BASE")
        .output()
        .unwrap();
    assert!(!failed.status.success());
    let stdout = String::from_utf8_lossy(&failed.stdout);
    let verdicts: Vec<_> = stdout
        .lines()
        .filter(|line| line.starts_with("lint-source: "))
        .collect();
    assert_eq!(
        verdicts,
        [
            "lint-source: terminal-custody: FAIL",
            "lint-source: copyout-debt: ok",
            "lint-source: test-lanes check: ok",
            "lint-source: probe-coverage: ok",
            "lint-source: probe-emitters check: ok",
            "lint-source: authority-debt --source-only: ok",
        ],
        "stdout: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&failed.stderr)
    );
    assert!(
        stdout.contains("expected value"),
        "ratchet diagnostic: {stdout}"
    );
}

#[test]
fn impact_is_an_explicit_feature_while_ci_changes_is_always_available() {
    use clap::CommandFactory;
    let command = carrick_xtask::cli::Cli::command();
    assert!(command.find_subcommand("ci-changes").is_some());
    assert_eq!(
        command.find_subcommand("impact").is_some(),
        cfg!(feature = "impact")
    );
}
