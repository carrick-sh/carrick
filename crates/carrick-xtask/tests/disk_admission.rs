#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use carrick_xtask::host_lease::{HostLease, HostLeaseMode};
use std::{
    fs,
    io::{BufRead, BufReader},
    os::unix::fs::PermissionsExt,
    path::Path,
    process::{Command, Stdio},
    time::Duration,
};
use yaml_rust2::YamlLoader;

fn command(root: &Path) -> Command {
    let df = root.join("df");
    fs::write(&df, "#!/bin/sh\nprintf 'Filesystem 1024-blocks Used Available Capacity Mounted\\n'\ncat \"$DISK_ROW\"\n").unwrap();
    fs::set_permissions(df, fs::Permissions::from_mode(0o755)).unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_carrick-xtask"));
    cmd.args(["check-disk", "--floor-gib", "20"])
        .current_dir(root)
        .env("PATH", format!("{}:/usr/bin:/bin", root.display()))
        .env("DISK_ROW", root.join("row"))
        .env("CARRICK_HOST_LEASE_PATH", root.join("lease"))
        .env_remove("CARRICK_HOST_LEASE_SOCKET");
    cmd
}

#[test]
fn shortage_without_holder_reports_numbers() {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("row"), "disk 999999999 0 1048576 0% /\n").unwrap();
    let out = command(root.path()).output().unwrap();
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("only 1 GiB free (floor 20 GiB)"), "{err}");
}

#[test]
fn busy_once_then_success_measures_only_after_shared_holder_drains() {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("row"), "disk 999999999 0 1048576 0% /\n").unwrap();
    let holder =
        HostLease::acquire_path(&root.path().join("lease"), HostLeaseMode::Carrick).unwrap();
    let mut child = command(root.path()).stderr(Stdio::piped()).spawn().unwrap();
    let stderr = child.stderr.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines() {
            let line = line.unwrap();
            if line.contains("host-lease: waiting") {
                tx.send(()).unwrap();
            }
        }
    });
    let waiting = rx.recv_timeout(Duration::from_secs(10));
    if waiting.is_err() {
        let _ = child.kill();
    }
    assert!(
        waiting.is_ok(),
        "disk command must wait on shared admission"
    );
    assert!(child.try_wait().unwrap().is_none());
    fs::write(root.path().join("row"), "disk 999999999 0 104857600 0% /\n").unwrap();
    drop(holder);
    assert!(child.wait().unwrap().success());
    reader.join().unwrap();
}

#[test]
fn hvf_bootstrap_and_disk_admission_use_installed_lease_runner() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let text = fs::read_to_string(root.join(".github/workflows/kernel-runtime.yml")).unwrap();
    let yaml = YamlLoader::load_from_str(&text).unwrap();
    let steps = yaml[0]["jobs"]["hvf-kernel"]["steps"].as_vec().unwrap();
    let disk = steps
        .iter()
        .find(|s| s["name"].as_str() == Some("Disk admission"))
        .unwrap();
    assert!(
        disk["run"]
            .as_str()
            .unwrap()
            .contains("/usr/local/bin/carrick-xtask host-lease --mode gate")
    );
    let bootstrap = steps
        .iter()
        .find(|s| s["name"].as_str() == Some("Build checkout xtask under shared lease"))
        .expect("checkout bootstrap must be leased");
    assert!(
        bootstrap["run"]
            .as_str()
            .unwrap()
            .contains("/usr/local/bin/carrick-xtask host-lease --mode carrick")
    );
}
