use std::fs;
use std::os::unix::fs::symlink;
use std::process::Command;
use std::time::{Duration, SystemTime};

#[test]
fn native_remote_protocol_needs_no_git_and_preserves_host_and_checkout_guards() {
    let temp = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(temp.path()).unwrap();
    let checkout = root.join("checkout");
    let artifact = checkout.join("target/debug/deps/old-output");
    fs::create_dir_all(artifact.parent().unwrap()).unwrap();
    fs::write(&artifact, "old").unwrap();
    fs::File::open(&artifact)
        .unwrap()
        .set_times(
            fs::FileTimes::new().set_modified(SystemTime::now() - Duration::from_secs(4 * 86_400)),
        )
        .unwrap();
    let alias = root.join("worktree-alias");
    symlink(&checkout, &alias).unwrap();
    let lock_path = root.join("host.lock");
    let invoke = |protocol: &str| {
        Command::new(env!("CARGO_BIN_EXE_carrick-xtask"))
            .args(["target-prune", "--protocol", protocol, "--dev-root"])
            .arg(&root)
            .arg("--target-dir")
            .arg(alias.join("target"))
            .arg("--apply")
            .env("CARRICK_HOST_LEASE_PATH", &lock_path)
            .output()
            .unwrap()
    };
    assert!(!invoke("pathname-v0").status.success());
    assert!(artifact.exists());
    fs::create_dir(root.join("gate-worktree.lock")).unwrap();
    let output = invoke("fd-v1");
    assert!(
        output.status.success()
            && artifact.exists()
            && String::from_utf8_lossy(&output.stdout).contains("checkout lock is held"),
        "{output:?}"
    );
    fs::remove_dir(root.join("gate-worktree.lock")).unwrap();
    let host = fs::File::create(&lock_path).unwrap();
    host.lock_shared().unwrap();
    let output = invoke("fd-v1");
    assert!(
        output.status.success()
            && artifact.exists()
            && String::from_utf8_lossy(&output.stdout).contains("host lease is held"),
        "{output:?}"
    );
    host.unlock().unwrap();
    let output = invoke("fd-v1");
    assert!(
        output.status.success()
            && !artifact.exists()
            && String::from_utf8_lossy(&output.stdout).contains("pruned"),
        "{output:?}"
    );
    assert!(!root.join("gate-worktree.lock").exists());
}
