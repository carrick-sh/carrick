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
    assert!(combined.contains("--keep-worktree"));
}
