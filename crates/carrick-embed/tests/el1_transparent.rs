//! Signed EL1 transparent execution verification.
//!
//! Run ONLY through `just test-embed` (scripts/test-signed.sh).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::sync::atomic::Ordering;

use carrick_embed::{ContainerBuilder, read_el1_counters, reset_el1_counters};
use carrick_image::PullPolicy;

#[test]
fn el1_transparent_smoke() {
    let _guard = common::guest_lock();
    reset_el1_counters();

    let result = common::run_or_fail(
        ContainerBuilder::from_image(common::SMOKE_IMAGE)
            .pull_policy(PullPolicy::Missing)
            .command(["/bin/sh", "-c", "echo hi"])
            .run_blocking(),
    );

    assert!(result.success(), "exit_code={}", result.exit_code);
    assert_eq!(result.stdout_utf8(), "hi\n");

    let counters = read_el1_counters().expect("EL1 counters should be populated");
    // Linux aarch64 syscall 64 is sys_write.
    let writes = counters.forwarded[64].load(Ordering::Relaxed);
    assert!(
        writes > 0,
        "expected write (64) syscalls to be forwarded through EL1, got {writes}"
    );
}

#[test]
fn el1_transparent_fork_exec_shared_backing() {
    let _guard = common::guest_lock();
    reset_el1_counters();

    // A guest that forks a child that performs 5 writes, waits for it, then execs a program that writes.
    let result = common::run_or_fail(
        ContainerBuilder::from_image(common::SMOKE_IMAGE)
            .pull_policy(PullPolicy::Missing)
            .command([
                "/bin/sh",
                "-c",
                "(for i in 1 2 3 4 5; do echo \"child_$i\"; done) & wait $! && exec /bin/echo \"exec_done\"",
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
