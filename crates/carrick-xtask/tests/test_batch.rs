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
}
