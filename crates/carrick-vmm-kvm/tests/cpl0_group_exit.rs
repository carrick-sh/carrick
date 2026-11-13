//! #2282: the parent must reap a fork child with two live members.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
#![allow(clippy::expect_used, clippy::panic)]
#[path = "common/kvm_pool_fixture.rs"]
#[allow(dead_code)]
mod kvm_pool_fixture;

fn group_exit(flags: &[&str], test: &str) {
    if std::env::var_os("CARRICK_GROUP_EXIT_CHILD").is_none() {
        let output = std::process::Command::new("timeout")
            .args(["--signal=KILL", "60"])
            .arg(std::env::current_exe().expect("test executable"))
            .args(["--exact", test, "--nocapture", "--test-threads=1"])
            .env("CARRICK_GROUP_EXIT_CHILD", "1")
            .output()
            .expect("bounded group-exit witness");
        assert!(
            output.status.success(),
            "group exit must finish: {:?}\n{}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    let elf = kvm_pool_fixture::assemble_fixture("native_group_exit.S", flags);
    let outcome = kvm_pool_fixture::run_pool_fixture(&elf, 256);
    assert_eq!(outcome.run.exit_code, 0, "parent must reap status 5");
}

#[test]
fn fork_child_exit_group_retires_futex_worker() {
    group_exit(&[], "fork_child_exit_group_retires_futex_worker");
}

#[test]
fn fork_child_exit_group_retires_runnable_worker() {
    group_exit(
        &["-DRUNNABLE_WORKER"],
        "fork_child_exit_group_retires_runnable_worker",
    );
}

#[test]
fn fork_child_exit_group_retires_computing_worker() {
    group_exit(
        &["-DCOMPUTING_WORKER"],
        "fork_child_exit_group_retires_computing_worker",
    );
}
