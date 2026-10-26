//! Signed EL1 fork + exec verification over shared backing.
//!
//! Run ONLY through `just test-embed` (scripts/test-signed.sh). Kept in its
//! own test binary so a parent-side wait failure here (#285) cannot take
//! `el1_transparent_smoke` down with it: the harness reaps per binary.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::sync::atomic::Ordering;
use std::time::Duration;

use carrick_embed::{ContainerBuilder, read_el1_counters, reset_el1_counters};
use carrick_image::PullPolicy;

#[test]
fn el1_transparent_fork_exec_shared_backing() {
    let _guard = common::guest_lock();
    let _watchdog = common::Watchdog::start(Duration::from_secs(90));
    reset_el1_counters();

    // The forked child writes four lines and execs echo for the fifth. The
    // parent waits for its normal exit, then execs a program that writes.
    let result = common::run_or_fail(
        ContainerBuilder::from_image(common::SMOKE_IMAGE)
            .pull_policy(PullPolicy::Missing)
            .command([
                "/bin/sh",
                "-c",
                "(for i in 1 2 3 4; do echo \"child_$i\"; done; exec /bin/echo \"child_5\") & wait $! && exec /bin/echo \"exec_done\"",
            ])
            .run_blocking(),
    );

    assert!(result.success(), "exit_code={}", result.exit_code);
    assert_eq!(
        result.stdout_utf8(),
        "child_1\nchild_2\nchild_3\nchild_4\nchild_5\nexec_done\n"
    );

    let counters = read_el1_counters().expect("EL1 counters should be populated");
    let forwarded_writes = counters.forwarded[64].load(Ordering::Relaxed);
    // At least 6 writes (5 from the forked child + 1 from the exec'd program).
    assert!(
        forwarded_writes >= 6,
        "expected at least 6 write syscalls across fork and exec in shared EL1 counters, got {forwarded_writes}"
    );
}

#[test]
fn native_root_exec_replaces_pid1_shell() {
    let _guard = common::guest_lock();
    let _watchdog = common::Watchdog::start(Duration::from_secs(90));
    let result = common::run_or_fail(
        ContainerBuilder::from_image(common::SMOKE_IMAGE)
            .pull_policy(PullPolicy::Missing)
            .command(["/bin/sh", "-c", "exec /bin/echo pid1_exec_ok"])
            .run_blocking(),
    );
    assert!(result.success(), "stderr={}", result.stderr_utf8());
    assert_eq!(result.stdout_utf8(), "pid1_exec_ok\n");
}

#[test]
fn native_child_exec_after_reusing_a_retired_slot() {
    let _guard = common::guest_lock();
    let _watchdog = common::Watchdog::start(Duration::from_secs(90));
    // Signed smoke for the fork/exit/exec composition. Numeric slot reuse is
    // deterministic only in the VM-free
    // `first_exec_after_fork_exit_reuses_the_slot_with_a_fresh_root_incarnation`
    // witness because the live allocator hashes the successor MM.
    let result = common::run_or_fail(
        ContainerBuilder::from_image(common::SMOKE_IMAGE)
            .pull_policy(PullPolicy::Missing)
            .command([
                "/bin/sh",
                "-c",
                "(exit 0) & first=$!; wait $first; (exec /bin/echo reused_slot_exec_ok) & second=$!; wait $second",
            ])
            .run_blocking(),
    );
    assert!(result.success(), "stderr={}", result.stderr_utf8());
    assert_eq!(result.stdout_utf8(), "reused_slot_exec_ok\n");
}

#[test]
fn native_exec_successor_blocks_in_nanosleep() {
    let _guard = common::guest_lock();
    let _watchdog = common::Watchdog::start(Duration::from_secs(90));
    let result = common::run_or_fail(
        ContainerBuilder::from_image(common::SMOKE_IMAGE)
            .pull_policy(PullPolicy::Missing)
            .command(["/bin/sh", "-c", "exec /bin/sleep 1"])
            .run_blocking(),
    );
    assert!(result.success(), "stderr={}", result.stderr_utf8());
    assert_eq!(result.stdout_utf8(), "");
}

#[test]
fn native_exec_successor_blocks_on_pipe_until_parent_writes() {
    const PARENT: &str = "carrick-linux-aarch64-two-pipes-dup3-exec";
    const CHILD: &str = "carrick-linux-aarch64-read-then-write-via-stdio";

    let _guard = common::guest_lock();
    let _watchdog = common::Watchdog::start(Duration::from_secs(90));
    let fixture_dir = common::repo_root()
        .join("fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release");
    for fixture in [PARENT, CHILD] {
        assert!(
            fixture_dir.join(fixture).is_file(),
            "missing {fixture}; run scripts/build-linux-fixtures.sh first"
        );
    }
    let result = common::run_or_fail(
        ContainerBuilder::from_image(common::SMOKE_IMAGE)
            .pull_policy(PullPolicy::Missing)
            .command([format!("/p/{PARENT}"), format!("/p/{CHILD}")])
            .mount_readonly(fixture_dir.to_string_lossy(), "/p")
            .run_blocking(),
    );
    assert!(result.success(), "stderr={}", result.stderr_utf8());
    assert_eq!(result.stdout_utf8(), "got:URI-REQUEST\n");
}
