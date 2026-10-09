//! Signed ARM crossing policy and terminal-completion witness.
//! Run only through `just test-embed arm_ring_first_`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use carrick_embed::{ContainerBuilder, read_el1_counters, reset_el1_counters};
use carrick_image::PullPolicy;
use std::sync::atomic::Ordering;

fn witness(strict: bool) {
    let _guard = common::guest_lock();
    reset_el1_counters();
    let path = common::repo_root().join(
        "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-ring-first",
    );
    assert!(
        path.is_file(),
        "signed fixture bundle must contain {}",
        path.display()
    );
    let result = common::run_or_fail(
        ContainerBuilder::from_image(common::SMOKE_IMAGE)
            .arm_ring_first(if strict {
                carrick_embed::ArmRingFirst::Strict
            } else {
                carrick_embed::ArmRingFirst::OptOut
            })
            .pull_policy(PullPolicy::Missing)
            .command(["/p/carrick-linux-aarch64-ring-first"])
            .mount_readonly(
                path.parent().expect("fixture directory").to_string_lossy(),
                "/p",
            )
            .run_blocking(),
    );
    assert!(
        result.success(),
        "exit={} stdout={} stderr={}",
        result.exit_code,
        result.stdout_utf8(),
        result.stderr_utf8()
    );
    assert_eq!(
        result.stdout_utf8(),
        if strict {
            "ring-first strict\n"
        } else {
            "ring-first forward\n"
        }
    );
    let counters = read_el1_counters().expect("EL1 counters populated");
    let refused = counters.refused[174].load(Ordering::Relaxed);
    let forwarded = counters.forwarded[174].load(Ordering::Relaxed);
    println!(
        "ring-first strict={strict} getuid refused={refused} forwarded={forwarded} exit_group refused={} forwarded={}",
        counters.refused[94].load(Ordering::Relaxed),
        counters.forwarded[94].load(Ordering::Relaxed)
    );
    assert_eq!(refused, u64::from(strict));
    assert_eq!(forwarded, u64::from(!strict));
    assert_eq!(counters.refused[94].load(Ordering::Relaxed), 0);
    assert_eq!(counters.forwarded[94].load(Ordering::Relaxed), 1);
    assert_eq!(counters.refused[172].load(Ordering::Relaxed), 0);
    assert_eq!(counters.refused[113].load(Ordering::Relaxed), 0);
    assert_eq!(counters.forwarded[113].load(Ordering::Relaxed), 1);
}

#[test]
fn arm_ring_first_strict_refusal_witness() {
    witness(true);
}
#[test]
fn arm_ring_first_hatch_disabled_forward_witness() {
    witness(false);
}
