#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::process::Command;

#[test]
fn batch_builds_once_and_preserves_filters_serial_environment_and_failures() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("src")).unwrap();
    std::fs::write(
        dir.path().join("Cargo.toml"),
        "[package]\nname = 'batch-fixture'\nversion = '0.1.0'\nedition = '2021'\n[features]\nleft = []\nright = []\n",
    )
    .unwrap();
    std::fs::write(
        dir.path().join("src/lib.rs"),
        r#"
        /// ```
        /// assert_eq!(2 + 2, 4);
        /// ```
        pub fn documented() {}
        #[test] fn parallel() {
            assert!(std::path::Path::new("Cargo.toml").exists());
            assert!(cfg!(feature = "left") && cfg!(feature = "right"));
        }
        #[test] fn serial_host() {
            assert_eq!(std::env::var("RUST_TEST_THREADS").unwrap(), "1");
        }
        #[test] fn excluded() { panic!("filter lost"); }
    "#,
    )
    .unwrap();
    std::fs::write(dir.path().join("justfile"), "lanes:\n    cargo test --lib --features left -- --skip serial_host --skip excluded\n    env RUST_TEST_THREADS=1 cargo test --lib --features right serial_host\ndocs:\n    cargo test documented\nred:\n    cargo test --lib excluded\n").unwrap();
    assert!(
        Command::new("cargo")
            .args(["generate-lockfile", "--offline"])
            .current_dir(dir.path())
            .status()
            .unwrap()
            .success()
    );
    let run = |recipe| {
        Command::new(env!("CARGO_BIN_EXE_carrick-xtask"))
            .args(["--root", dir.path().to_str().unwrap(), "test-batch", recipe])
            .env("CARGO_TARGET_DIR", dir.path().join("target"))
            .env_remove("CARGO_LOG")
            .output()
            .unwrap()
    };
    let green = run("lanes");
    assert!(
        green.status.success(),
        "{}",
        String::from_utf8_lossy(&green.stderr)
    );
    assert!(String::from_utf8_lossy(&green.stderr).contains("test-batch: one compile"));
    let docs = run("docs");
    assert!(
        docs.status.success(),
        "{}",
        String::from_utf8_lossy(&docs.stderr)
    );
    assert!(
        String::from_utf8_lossy(&docs.stdout).contains("src/lib.rs"),
        "implicit doctests were lost"
    );
    let red = run("red");
    assert!(
        !red.status.success(),
        "a failing binary must fail the batch"
    );
    let compile_only = Command::new(env!("CARGO_BIN_EXE_carrick-xtask"))
        .args([
            "--root",
            dir.path().to_str().unwrap(),
            "test-batch",
            "--no-run",
            "red",
        ])
        .env("CARGO_TARGET_DIR", dir.path().join("target"))
        .env_remove("CARGO_LOG")
        .output()
        .unwrap();
    assert!(
        compile_only.status.success(),
        "--no-run executed a failing test"
    );
}

#[test]
fn exported_batch_runs_without_compiling_and_rejects_missing_or_changed_inputs() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    std::fs::create_dir(root.join("src")).unwrap();
    std::fs::write(root.join("Cargo.toml"), "[package]\nname='archived-batch'\nversion='0.1.0'\nedition='2021'\n[features]\nwitness=[]\n").unwrap();
    std::fs::write(root.join("src/lib.rs"), "#[test] fn green() { assert!(cfg!(feature=\"witness\")); }\n#[test] fn red() { panic!(\"filter lost\"); }\n").unwrap();
    std::fs::write(
        root.join("src/main.rs"),
        "fn main() { println!(\"fixture CLI\"); }",
    )
    .unwrap();
    std::fs::create_dir(root.join("tests")).unwrap();
    std::fs::write(root.join("tests/smoke.rs"), r#"#[test] fn cli_fixture() {
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_archived-batch")).output().unwrap();
        assert!(out.status.success());
        assert_eq!(out.stdout, b"fixture CLI\n");
    }"#).unwrap();
    std::fs::write(root.join("justfile"), "lanes:\n    cargo test --all-features --lib --test smoke -- --skip red\nred:\n    cargo test --all-features --lib -- red\nchanged:\n    cargo test --lib\n").unwrap();
    assert!(
        Command::new("cargo")
            .args(["generate-lockfile", "--offline"])
            .current_dir(root)
            .status()
            .unwrap()
            .success()
    );
    let run = |extra: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_carrick-xtask"))
            .args(["--root", root.to_str().unwrap(), "test-batch"])
            .args(extra)
            .env("CARGO_TARGET_DIR", root.join("target"))
            .output()
            .unwrap()
    };
    let export = run(&["--export", "target/tests.tar.gz", "lanes"]);
    assert!(
        export.status.success(),
        "{}",
        String::from_utf8_lossy(&export.stderr)
    );
    std::fs::rename(root.join("target"), root.join("saved-target")).unwrap();
    let tar = std::fs::File::open(root.join("saved-target/tests.tar.gz")).unwrap();
    tar::Archive::new(flate2::read::GzDecoder::new(tar))
        .unpack(root)
        .unwrap();
    let import = |recipe| run(&["--artifacts", "target/test-batch.json", recipe]);
    let green = import("lanes");
    assert!(
        green.status.success(),
        "{}",
        String::from_utf8_lossy(&green.stderr)
    );
    assert!(!String::from_utf8_lossy(&green.stderr).contains("one compile"));
    assert!(
        !import("red").status.success(),
        "test failure must propagate"
    );
    assert!(
        !import("changed").status.success(),
        "feature drift must fail closed"
    );
    let saved_manifest = std::fs::read(root.join("target/test-batch.json")).unwrap();
    let mut wrong_root: serde_json::Value = serde_json::from_slice(&saved_manifest).unwrap();
    wrong_root["root"] = "/another/checkout".into();
    std::fs::write(
        root.join("target/test-batch.json"),
        serde_json::to_vec(&wrong_root).unwrap(),
    )
    .unwrap();
    assert!(
        !import("lanes").status.success(),
        "checkout relocation must fail closed"
    );
    std::fs::write(root.join("target/test-batch.json"), &saved_manifest).unwrap();
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.join("target/test-batch.json")).unwrap())
            .unwrap();
    std::fs::remove_file(root.join(manifest["binaries"][0]["path"].as_str().unwrap())).unwrap();
    assert!(
        !import("lanes").status.success(),
        "missing binary must fail closed"
    );
}
