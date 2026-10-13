//! Signed EL1 transparent execution verification.
//!
//! Run ONLY through `just test-embed` (scripts/test-signed.sh).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::sync::atomic::Ordering;
use std::time::Duration;

use carrick_embed::{ContainerBuilder, read_el1_counters, reset_el1_counters};
use carrick_image::PullPolicy;

#[test]
fn el1_transparent_smoke() {
    let _guard = common::guest_lock();
    let _watchdog = common::Watchdog::start(Duration::from_secs(90));
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
