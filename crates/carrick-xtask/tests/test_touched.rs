#![allow(clippy::unwrap_used, clippy::expect_used)]
use std::process::Command;

#[test]
fn recipe_authority_preserves_features_partitions_and_reverse_dependencies() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let write = |path: &str, data: &str| {
        let path = root.join(path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, data).unwrap();
    };
    write(
        "Cargo.toml",
        "[workspace]\nmembers=['sched','kernel','unrelated']\nresolver='2'\n",
    );
    write(
        "sched/Cargo.toml",
        "[package]\nname='carrick-sched-core'\nversion='0.1.0'\nedition='2021'\n",
    );
    write(
        "sched/src/lib.rs",
        "#[test] fn regular() {}\n#[test] fn serial_host() { assert_eq!(std::env::var(\"RUST_TEST_THREADS\").unwrap(), \"1\"); }\n",
    );
    write(
        "kernel/Cargo.toml",
        "[package]\nname='carrick-kernel'\nversion='0.1.0'\nedition='2021'\n[features]\ntest-support=[]\n[dependencies]\ncarrick-sched-core={path='../sched'}\n",
    );
    write(
        "kernel/src/lib.rs",
        "#[test] fn needs_support() { assert!(cfg!(feature=\"test-support\")); }\n",
    );
    write(
        "unrelated/Cargo.toml",
        "[package]\nname='unrelated'\nversion='0.1.0'\nedition='2021'\n",
    );
    write(
        "unrelated/src/lib.rs",
        "#[test] fn must_not_run() { panic!(\"unrelated test executed\"); }\n",
    );
    write(
        "scripts/migrate/check-serial-host-tests.py",
        "# fixture authority\n",
    );
    let recipe = "test:\n    cargo --locked --offline test --workspace --lib --features carrick-kernel/test-support -- --skip serial_host\n    env RUST_TEST_THREADS=1 cargo --locked --offline test --workspace --lib --features carrick-kernel/test-support serial_host\n";
    write("justfile", recipe);
    let git = |args: &[&str]| {
        let out = Command::new("git")
            .args(args)
            .current_dir(root)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap().trim().to_owned()
    };
    let lock = Command::new("cargo")
        .args(["generate-lockfile", "--offline"])
        .current_dir(root)
        .output()
        .unwrap();
    assert!(lock.status.success());
    git(&["init", "-q"]);
    git(&["add", "."]);
    git(&[
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@example.com",
        "commit",
        "-qm",
        "base",
    ]);
    let base = git(&["rev-parse", "HEAD"]);
    write(
        "sched/src/lib.rs",
        "#[test] fn cancelled_metadata_wait_releases_record_without_resume() { panic!(\"known regression\"); }\n#[test] fn serial_host_cancelled_deferred_metadata_wait_releases_record_without_resume() { assert_eq!(std::env::var(\"RUST_TEST_THREADS\").unwrap(), \"1\"); panic!(\"known regression\"); }\n",
    );
    git(&["add", "sched/src/lib.rs"]);
    git(&[
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@example.com",
        "commit",
        "-qm",
        "regression",
    ]);
    let run = |plan: bool| {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_carrick-xtask"));
        cmd.args(["--root", root.to_str().unwrap(), "test-touched", &base]);
        if plan {
            cmd.arg("--plan");
        }
        cmd.env("CARGO_TARGET_DIR", root.join("target"))
            .env("JOBS", "1")
            .output()
            .unwrap()
    };
    let plan = run(true);
    assert!(
        plan.status.success(),
        "{}",
        String::from_utf8_lossy(&plan.stderr)
    );
    let output = String::from_utf8_lossy(&plan.stdout);
    assert!(output.contains("test-touched: carrick-sched-core"));
    assert!(output.contains("test-touched: carrick-kernel"));
    assert!(!output.contains("test-touched: unrelated"));
    assert!(output.contains("carrick-kernel/test-support"));
    let replay = run(false);
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&replay.stdout),
        String::from_utf8_lossy(&replay.stderr)
    );
    assert!(!replay.status.success(), "{text}");
    assert!(
        text.contains("cancelled_metadata_wait_releases_record_without_resume ... FAILED"),
        "{text}"
    );
    assert!(
        text.contains(
            "serial_host_cancelled_deferred_metadata_wait_releases_record_without_resume ... FAILED"
        ),
        "{text}"
    );
    assert!(!text.contains("must_not_run ... FAILED"), "{text}");
    // Editing the authority changes the touched plan immediately; no second table.
    write(
        "justfile",
        &recipe.replace("test-support", "changed-feature"),
    );
    let plan = run(true);
    assert!(String::from_utf8_lossy(&plan.stdout).contains("changed-feature"));
}
