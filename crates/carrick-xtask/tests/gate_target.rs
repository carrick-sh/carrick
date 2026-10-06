use std::fs;
use std::process::Command;

#[test]
fn cleanup_requires_owner_and_honors_keep_target() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("gate-worktree");
    let lock = temp.path().join("gate-worktree.lock");
    fs::create_dir_all(root.join("target/release")).unwrap();
    fs::create_dir(&lock).unwrap();
    fs::write(lock.join("run_id"), "owner-run\n").unwrap();
    fs::write(root.join("target/release/output"), "binary").unwrap();
    fs::create_dir_all(root.join("target/el1-gate")).unwrap();
    fs::write(root.join("target/el1-gate/receipt.json"), "receipt").unwrap();
    for (owner, keep, success, output_exists) in [
        ("other-run", false, false, true),
        ("owner-run", true, true, true),
        ("owner-run", false, true, false),
    ] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_carrick-xtask"));
        command
            .args(["gate-cleanup", "--owned-root"])
            .arg(&root)
            .args(["--run-id", owner])
            .env_remove("CARRICK_HOST_LEASE_SOCKET")
            .env_remove("CARRICK_GATE_KEEP_TARGET");
        if keep {
            command.env("CARRICK_GATE_KEEP_TARGET", "1");
        }
        let result = command.output().unwrap();
        assert_eq!(
            result.status.success(),
            success,
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert_eq!(root.join("target/release/output").exists(), output_exists);
        assert!(root.join("target/el1-gate/receipt.json").exists());
    }
}
