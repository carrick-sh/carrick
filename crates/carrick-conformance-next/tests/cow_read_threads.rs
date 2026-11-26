//! Signed ARM production witness for #3042: a native fork child's two live
//! threads read(2) into one copy-on-write page at once. The kernel's copy is
//! the page's first write in the child, so the user-copy supply must serve
//! the fork child's copy-on-write stock; HVF refused it ("no guest COW
//! state"), and the read failed with EFAULT or the child died. The KVM half
//! is `production_fork_child_threads_read_into_one_copy_on_write_page`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use carrick_conformance_next::{PullPolicy, ResultAssert, TestContainer};

fn run_case(as_child: bool) {
    let _guard = common::guest_lock();
    let root = common::repo_root();
    let fixture = root.join("crates/carrick-conformance-next/tests/fixtures/cow-read-threads");
    let source_hash = carrick_xtask::provision::compute_sha256(&fixture.join("src/main.rs"))
        .expect("hash cow-read-threads source");
    let probe =
        root.join("target/cow-read-threads/aarch64-unknown-linux-musl/release/cow-read-threads");
    let binary_hash = carrick_xtask::provision::compute_sha256(&probe)
        .expect("signed runner builds cow-read-threads");
    eprintln!(
        "COW_READ_THREADS as_child={as_child} source_sha256={source_hash} binary_sha256={binary_hash}"
    );
    // `exec` makes the probe the root process, whose forks are native
    // children; without it the probe is itself a native fork child of the
    // shell and its forks are grandchildren.
    let cmd = if as_child {
        "/tmp/cow-read-threads"
    } else {
        "exec /tmp/cow-read-threads"
    };
    let (result, _) = common::run_or_fail(
        TestContainer::new(common::SMOKE_IMAGE)
            .pull_policy(PullPolicy::Missing)
            .mount_readonly(probe.display().to_string(), "/tmp/cow-read-threads")
            .run_with_audit(["/bin/sh", "-c", cmd]),
    );
    assert_eq!(
        result.stdout_utf8(),
        format!("source_sha256={source_hash}\nrounds=32\nthreads=2\ncow_read_ok=true\n"),
        "the first round that differs from Linux; stderr: {}",
        result.stderr_utf8()
    );
    result.assert_success();
    result.assert_exit_code(0);
    assert_eq!(result.signal, None);
    assert!(!result.trap_limit_hit);
    assert_eq!(result.terminal_reason, None);
    assert!(result.stderr.is_empty(), "{}", result.stderr_utf8());
}

#[test]
fn case_arm_fork_child_threads_read_into_one_copy_on_write_page() {
    run_case(false);
    run_case(true);
}
