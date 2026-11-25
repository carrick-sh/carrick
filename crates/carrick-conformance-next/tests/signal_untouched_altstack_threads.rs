//! Signed ARM production witness for #3004: signal handlers on mapped,
//! never-touched alternate stacks across two live clone threads.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use carrick_conformance_next::{PullPolicy, ResultAssert, TestContainer};

fn run_case(as_child: bool) {
    let _guard = common::guest_lock();
    let root = common::repo_root();
    let fixture = root
        .join("crates/carrick-conformance-next/tests/fixtures/signal-untouched-altstack-threads");
    let source_hash = carrick_xtask::provision::compute_sha256(&fixture.join("src/main.rs"))
        .expect("hash signal-untouched-altstack-threads source");
    let probe = root.join(
        "target/signal-untouched-altstack-threads/aarch64-unknown-linux-musl/release/signal-untouched-altstack-threads",
    );
    let binary_hash = carrick_xtask::provision::compute_sha256(&probe)
        .expect("signed runner builds signal-untouched-altstack-threads");
    eprintln!(
        "SIGNAL_UNTOUCHED_ALTSTACK_THREADS as_child={as_child} source_sha256={source_hash} binary_sha256={binary_hash}"
    );
    let cmd = if as_child {
        "/tmp/signal-untouched-altstack-threads"
    } else {
        "exec /tmp/signal-untouched-altstack-threads"
    };
    let (result, _) = common::run_or_fail(
        TestContainer::new(common::SMOKE_IMAGE)
            .pull_policy(PullPolicy::Missing)
            .mount_readonly(
                probe.display().to_string(),
                "/tmp/signal-untouched-altstack-threads",
            )
            .run_with_audit(["/bin/sh", "-c", cmd]),
    );
    result.assert_success();
    result.assert_exit_code(0);
    assert_eq!(result.signal, None);
    assert!(!result.trap_limit_hit);
    assert_eq!(result.terminal_reason, None);
    assert_eq!(
        result.stdout_utf8(),
        format!("source_sha256={source_hash}\nthreads=2\nrounds=200\nuntouched_altstack_ok=true\n")
    );
    assert!(result.stderr.is_empty(), "{}", result.stderr_utf8());
}

#[test]
fn case_arm_thread_handlers_run_on_untouched_alternate_stacks() {
    run_case(false);
    run_case(true);
}
