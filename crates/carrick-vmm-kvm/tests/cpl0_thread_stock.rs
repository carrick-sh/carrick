//! #2734: a process holds as many live ring-born threads as Linux allows,
//! not one stock page's worth. Real KVM production CPL0 image and executor
//! pool; the members run as the root process and as a forked native child.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
#![allow(clippy::expect_used, clippy::panic)]
#[path = "common/kvm_pool_fixture.rs"]
#[allow(dead_code)]
mod kvm_pool_fixture;

/// Run `native_thread_stock.S` built with `flags` in a bounded child test
/// process; the run's exit code is the fixture's verdict (0, or the
/// failing clone, tid or join it encodes).
fn thread_stock(flags: &[&str], test: &str) {
    if std::env::var_os("CARRICK_THREAD_STOCK_CHILD").is_none() {
        let output = std::process::Command::new("timeout")
            .args(["--signal=KILL", "120"])
            .arg(std::env::current_exe().expect("test executable"))
            .args(["--exact", test, "--nocapture", "--test-threads=1"])
            .env("CARRICK_THREAD_STOCK_CHILD", "1")
            .output()
            .expect("bounded thread-stock witness");
        assert!(
            output.status.success(),
            "thread-stock witness must finish: {:?}\n{}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    let elf = kvm_pool_fixture::assemble_fixture("native_thread_stock.S", flags);
    let outcome = kvm_pool_fixture::try_run_pool_fixture_with(&elf, 4096, |_| {})
        .expect("production CPL0 thread stock");
    assert_eq!(
        outcome.run.exit_code, 0,
        "exit 100+i: clone #i was EAGAIN; 140+i: clone #i failed otherwise; \
         60+i: tid #i skipped identities; 91: fork, wait4 or join failed"
    );
    assert_eq!(outcome.run.terminating_signal, None);
    // Cost: every clone is served in ring, none forwarded to the host.
    assert_eq!(
        outcome
            .physical
            .refusal_count(carrick_abi::NativeNr(56))
            .expect("clone refusal counter"),
        0,
        "clone must be served in ring"
    );
}

/// Sixteen live threads parked in futex waits in the root process, then a
/// non-last raw exit, then exit_group with every worker still parked.
#[test]
fn root_holds_sixteen_live_threads_then_exit_group() {
    thread_stock(&[], "root_holds_sixteen_live_threads_then_exit_group");
}

/// The same members in a forked native child, reaped by the root.
#[test]
fn fork_child_holds_sixteen_live_threads_then_exit_group() {
    thread_stock(
        &["-DFORK_CHILD"],
        "fork_child_holds_sixteen_live_threads_then_exit_group",
    );
}

/// Twenty-four threads created and joined one at a time in a fork child.
#[test]
fn fork_child_creates_and_joins_twenty_four_threads() {
    thread_stock(
        &["-DFORK_CHILD", "-DCHURN", "-DLIVE=24"],
        "fork_child_creates_and_joins_twenty_four_threads",
    );
}

/// Twenty-four threads created and joined one at a time in the root.
#[test]
fn root_creates_and_joins_twenty_four_threads() {
    thread_stock(
        &["-DCHURN", "-DLIVE=24"],
        "root_creates_and_joins_twenty_four_threads",
    );
}
