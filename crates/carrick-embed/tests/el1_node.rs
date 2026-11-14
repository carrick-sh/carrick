//! Node scoreboard acceptance through the signed HVF path (#1671).
//! Run only through scripts/test-signed.sh.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use carrick_embed::ContainerBuilder;
use carrick_image::PullPolicy;

fn node(script: &str) -> String {
    let _guard = common::guest_lock();
    carrick_embed::reset_el1_counters();
    let result = common::run_or_fail(
        ContainerBuilder::from_image("node:22-slim")
            .pull_policy(PullPolicy::Missing)
            .workdir("/tmp")
            .command(["node", "-e", script])
            .run_blocking(),
    );
    let mut diagnostics = String::new();
    if let Some(counters) = carrick_embed::read_el1_counters() {
        counters
            .write_futex_errors(&mut diagnostics)
            .expect("format diagnostics");
    }
    assert!(
        result.success(),
        "Node exit={} stdout={} stderr={} ring diagnostics={}",
        result.exit_code,
        result.stdout_utf8(),
        result.stderr_utf8(),
        diagnostics
    );
    result.stdout_utf8().trim().to_owned()
}

#[test]
#[ignore = "flaky: glibc futex abort in 30-50% of runs (#2288); run with --include-ignored for populations"]
fn el1_node_version() {
    assert!(node("console.log(process.version)").starts_with("v22."));
}

#[test]
#[ignore = "red on main: spawnSync /bin/sh ENOSYS then uv__io_poll (#1671, ARM Node lane next stop); run with --include-ignored"]
fn el1_node_child() {
    assert_eq!(
        node("console.log(require('child_process').execSync('echo child-ok').toString().trim())"),
        "child-ok"
    );
}
