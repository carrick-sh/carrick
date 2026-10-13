use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::Path;
use std::process::Command;
use std::time::{Duration, SystemTime};

#[test]
fn native_remote_protocol_needs_no_git_and_preserves_host_and_checkout_guards() {
    let write_executable = |path: &Path, script: &str| {
        fs::write(path, script).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    };
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
    let bin = root.join("bin");
    fs::create_dir(&bin).unwrap();
    for name in ["sudo", "lsof"] {
        write_executable(
            &bin.join(name),
            "#!/bin/sh\necho 'sudo: a password is required' >&2\nexit 1\n",
        );
    }
    let path_env = std::env::join_paths(
        std::iter::once(bin.clone()).chain(
            std::env::var_os("PATH")
                .as_deref()
                .into_iter()
                .flat_map(std::env::split_paths),
        ),
    )
    .unwrap();
    let invoke = |protocol: &str| {
        Command::new(env!("CARGO_BIN_EXE_carrick-xtask"))
            .args(["target-prune", "--protocol", protocol, "--dev-root"])
            .arg(&root)
            .arg("--target-dir")
            .arg(alias.join("target"))
            .arg("--apply")
            .env("CARRICK_HOST_LEASE_PATH", &lock_path)
            .env("PATH", &path_env)
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
    let denied = invoke("fd-v1");
    let denied_stdout = String::from_utf8_lossy(&denied.stdout);
    assert!(
        denied.status.success()
            && artifact.exists()
            && denied_stdout.contains(
                "keep target (in use or unknown visibility: lsof exit 1, stderr: sudo: a password is required)"
            ),
        "{denied:?}"
    );
    fs::remove_file(bin.join("lsof")).unwrap();
    write_executable(
        &bin.join("sudo"),
        "#!/bin/sh\nif [ \"$1\" != \"-n\" ] || [ \"$2\" != \"-u\" ] || [ \"$3\" != \"root\" ]; then\n    echo \"unexpected sudo args: $*\" >&2\n    exit 2\nfi\nshift 3\nexec \"$@\"\n",
    );
    let held = fs::File::open(&artifact).unwrap();
    let busy = invoke("fd-v1");
    let busy_stdout = String::from_utf8_lossy(&busy.stdout);
    assert!(
        busy.status.success()
            && artifact.exists()
            && busy_stdout
                .contains("keep target (in use or unknown visibility: unmatched record: p"),
        "{busy:?}"
    );
    drop(held);
    let output = invoke("fd-v1");
    assert!(
        output.status.success()
            && !artifact.exists()
            && String::from_utf8_lossy(&output.stdout).contains("pruned"),
        "{output:?}"
    );
    assert!(!root.join("gate-worktree.lock").exists());
}
