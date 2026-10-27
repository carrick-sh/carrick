#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[test]
fn deadline_names_unfinished_test_reaps_process_and_preserves_results() {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir(dir.path().join("src")).unwrap();
    fs::write(dir.path().join("Cargo.toml"), "[package]\nname='loom-watchdog-fixture'\nversion='0.1.0'\nedition='2021'\n[features]\nloom=[]\n").unwrap();
    fs::write(
        dir.path().join("src/lib.rs"),
        r#"
        #[test] fn passing() { assert!(cfg!(feature = "loom")); }
        #[test] fn sleeping() {
            std::fs::write("sleeping.pid", std::process::id().to_string()).unwrap();
            let child = std::process::Command::new("sleep").arg("3600").spawn().unwrap();
            std::fs::write("descendant.pid", child.id().to_string()).unwrap();
            loop { std::thread::sleep(std::time::Duration::from_secs(3600)); }
        }
        #[test] fn failing() { panic!("ordinary failure witness"); }
    "#,
    )
    .unwrap();
    fs::write(dir.path().join("justfile"), "green:\n    cargo test --locked --features loom --lib passing\nred:\n    cargo test --locked --features loom --lib failing\nstall:\n    cargo test --locked --features loom --lib -- --skip failing\nduplicate:\n    cargo test --locked --features loom --lib passing\n    cargo test --locked --features loom --lib failing\nbad-build:\n    cargo test --locked --features missing --lib passing\n").unwrap();
    assert!(
        Command::new("cargo")
            .args(["generate-lockfile", "--offline"])
            .current_dir(dir.path())
            .status()
            .unwrap()
            .success()
    );
    let run = |recipe: &str| {
        let log = dir.path().join(format!("{recipe}.log"));
        let output = fs::File::create(&log).unwrap();
        let mut child = Command::new(env!("CARGO_BIN_EXE_carrick-xtask"))
            .args([
                "--root",
                dir.path().to_str().unwrap(),
                "loom-run",
                recipe,
                "--timeout-secs",
                "1",
            ])
            .env("CARGO_TARGET_DIR", dir.path().join("target"))
            .env_remove("RUST_TEST_THREADS")
            .stdout(Stdio::from(output.try_clone().unwrap()))
            .stderr(Stdio::from(output))
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(20);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() >= deadline {
                if let Ok(pid) = fs::read_to_string(dir.path().join("sleeping.pid")) {
                    let pid: i32 = pid.parse().unwrap();
                    // SAFETY: the fixture records its dedicated process group.
                    unsafe {
                        libc::kill(-pid, libc::SIGKILL);
                    }
                }
                child.kill().unwrap();
                child.wait().unwrap();
                panic!(
                    "runner exceeded fixture's outer deadline: {}",
                    fs::read_to_string(&log).unwrap()
                );
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        (status, fs::read_to_string(log).unwrap())
    };
    let (green, log) = run("green");
    assert!(green.success(), "{log}");
    assert!(log.contains("test passing ... ok"), "{log}");
    assert!(
        log.contains("BUILD start") && log.contains("BUILD end"),
        "{log}"
    );
    let (red, log) = run("red");
    assert_eq!(red.code(), Some(101), "{log}");
    assert!(log.contains("test failing ... FAILED"), "{log}");
    assert!(!log.contains("STALLED"), "{log}");
    let (red, log) = run("bad-build");
    assert!(!red.success(), "{log}");
    assert!(
        log.contains("BUILD end") && !log.contains("RUN start"),
        "{log}"
    );
    let (red, log) = run("duplicate");
    assert!(!red.success(), "{log}");
    assert_eq!(log.matches("BUILD start").count(), 1, "{log}");
    let started = Instant::now();
    let (stalled, log) = run("stall");
    assert!(!stalled.success(), "{log}");
    assert!(started.elapsed() < Duration::from_secs(10), "{log}");
    assert!(log.contains("loom-run: STALLED"), "{log}");
    assert!(
        log.contains("unfinished sleeping") && log.contains("elapsed"),
        "{log}"
    );
    assert!(!log.contains("unfinished passing"), "{log}");
    assert_process_gone(&dir.path().join("sleeping.pid"));
    assert_process_gone(&dir.path().join("descendant.pid"));
}

fn assert_process_gone(file: &std::path::Path) {
    let pid: i32 = fs::read_to_string(file).unwrap().parse().unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        // SAFETY: signal zero observes the fixture PID without sending a signal.
        if unsafe { libc::kill(pid, 0) } == -1 {
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::ESRCH)
            );
            break;
        }
        assert!(
            Instant::now() < deadline,
            "fixture process {pid} survived group cancellation"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}
