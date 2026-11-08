#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "support/cargo_env.rs"]
mod cargo_env;

use std::process::Command;

fn xtask_command() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_carrick-xtask"));
    cargo_env::clean_cargo_env(&mut command);
    command
}

#[test]
fn batch_builds_once_and_preserves_filters_serial_environment_and_failures() {
    batch_fixture(false);
}

#[test]
fn el1_batch_releases_fixture_memory_without_changing_population() {
    batch_fixture(true);
}

fn batch_fixture(isolated: bool) {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("src")).unwrap();
    std::fs::write(
        dir.path().join("Cargo.toml"),
        format!("[package]\nname = '{}'\nversion = '0.1.0'\nedition = '2021'\n[features]\nleft = []\nright = []\n", if isolated { "carrick-el1-linux" } else { "batch-fixture" }),
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
            assert_eq!(std::env::var("RUST_MIN_STACK").unwrap(), "8388608");
            assert!(cfg!(feature = "left") && cfg!(feature = "right"));
        }
        #[test] fn serial_host() {
            assert_eq!(std::env::var("RUST_TEST_THREADS").unwrap(), "1");
        }
        #[test] fn excluded() { panic!("filter lost"); }
    "#,
    )
    .unwrap();
    if isolated {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(dir.path().join("src/lib.rs"))
            .unwrap();
        file.write_all(r#"
        static RETAINED: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        #[test] fn retained_one() { assert_eq!(RETAINED.fetch_add(1, std::sync::atomic::Ordering::SeqCst), 0); }
        #[test] fn retained_two() { assert_eq!(RETAINED.fetch_add(1, std::sync::atomic::Ordering::SeqCst), 0); }
        #[test] #[ignore] fn intentionally_ignored() { panic!("ignore lost"); }
        "#.as_bytes()).unwrap();
    }
    std::fs::write(dir.path().join("justfile"), "lanes:\n    env RUST_MIN_STACK=8388608 cargo --locked --offline test --lib --features left -- --skip serial_host --skip excluded\n    env RUST_TEST_THREADS=1 cargo --locked --offline test --lib --features right serial_host\ndocs:\n    cargo --locked --offline test documented\nred:\n    cargo --locked --offline test --lib excluded\nsingle:\n    env RUST_MIN_STACK=8388608 cargo --locked --offline test --lib --features left,right -- --skip excluded --skip serial_host --test-threads=1\n").unwrap();
    std::fs::write(
        dir.path().join("Cargo.lock"),
        format!(
            "version = 4\n[[package]]\nname = \"{}\"\nversion = \"0.1.0\"\n",
            if isolated {
                "carrick-el1-linux"
            } else {
                "batch-fixture"
            }
        ),
    )
    .unwrap();
    let run = |recipe| {
        xtask_command()
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
    if isolated {
        let text = String::from_utf8_lossy(&green.stdout);
        assert!(text.contains("3 passed; 0 failed; 1 ignored;"), "{text}");
        assert!(text.contains("1 passed; 0 failed; 0 ignored;"), "{text}");
        assert!(String::from_utf8_lossy(&green.stderr).contains("test-isolated:"));
        let single = run("single");
        assert!(
            single.status.success(),
            "{}",
            String::from_utf8_lossy(&single.stderr)
        );
        assert!(String::from_utf8_lossy(&single.stderr).contains("jobs=1 selected=4"));
    }
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
    let compile_only = xtask_command()
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
    exported_batch_fixture(false);
}

#[cfg(unix)]
#[test]
fn exported_batch_accepts_symlinked_checkout_without_allowing_relocation() {
    exported_batch_fixture(true);
}

fn exported_batch_fixture(symlinked: bool) {
    let dir = tempfile::tempdir().unwrap();
    let alias = tempfile::tempdir().unwrap();
    let linked = alias.path().join("checkout");
    #[cfg(unix)]
    if symlinked {
        std::os::unix::fs::symlink(dir.path(), &linked).unwrap();
    }
    let root = if symlinked {
        linked.as_path()
    } else {
        dir.path()
    };
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
    std::fs::write(root.join("justfile"), "lanes:\n    cargo --locked --offline test --all-features --lib --test smoke -- --skip red\nred:\n    cargo --locked --offline test --all-features --lib -- red\nchanged:\n    cargo --locked --offline test --lib\n").unwrap();
    std::fs::write(
        root.join("Cargo.lock"),
        "version = 4\n[[package]]\nname = \"archived-batch\"\nversion = \"0.1.0\"\n",
    )
    .unwrap();
    let run = |extra: &[&str]| {
        xtask_command()
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
    if symlinked {
        let mut aliased_root: serde_json::Value = serde_json::from_slice(&saved_manifest).unwrap();
        aliased_root["root"] = root.to_str().unwrap().into();
        std::fs::write(
            root.join("target/test-batch.json"),
            serde_json::to_vec(&aliased_root).unwrap(),
        )
        .unwrap();
        assert!(
            import("lanes").status.success(),
            "equivalent checkout aliases must import"
        );
    }

    let mut wrong_root: serde_json::Value = serde_json::from_slice(&saved_manifest).unwrap();
    wrong_root["root"] = alias.path().to_str().unwrap().into();
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
