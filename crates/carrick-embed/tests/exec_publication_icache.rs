//! Signed contract `kernel.mm.exec-publication-icache`.
//!
//! Run ONLY through `just test-embed` (scripts/test-signed.sh).
//!
//! arm64 Linux makes a newly mapped executable page coherent with the
//! instruction cache, so a program may write instructions into a page it
//! just mapped and call them without its own `ic ivau` (mprotectexec's
//! shape). Carrick recycles frames that may hold previously executed code;
//! every EL0-executable publication crosses one instruction-cache authority
//! that invalidates a frame on its first executable publication. The fixture
//! executes code A in a region, releases it, maps a fresh region, writes code
//! B there without maintenance and requires B to run, in one process and
//! across a fork. A stale frame would return A's value.
//!
//! The behaviour is probabilistic (it needs the same physical frame back
//! with A's lines still cached): the deterministic gates are the funnel and
//! budget tests in carrick-mmu-core and carrick-vmm-hvf. This run proves the
//! end-to-end path stays correct.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use carrick_embed::ContainerBuilder;
use carrick_image::PullPolicy;

fn run(args: &[&str]) {
    let _guard = common::guest_lock();
    let watchdog = common::Watchdog::start(std::time::Duration::from_secs(180));
    let result = common::run_or_fail(
        ContainerBuilder::from_image(common::SMOKE_IMAGE)
            .pull_policy(PullPolicy::Missing)
            .command(std::iter::once("/opt/carrick/icache-reuse").chain(args.iter().copied()))
            .vfs_mount("/opt/carrick", Box::new(common::icache_reuse_vfs()))
            .run_blocking(),
    );
    watchdog.disarm();
    assert!(
        result.success() && result.stdout_utf8().starts_with("icache_reuse_ok"),
        "exit_code={} stdout={:?} stderr={}",
        result.exit_code,
        result.stdout_utf8(),
        result.stderr_utf8()
    );
}

#[test]
fn a_fresh_executable_page_runs_its_own_code_after_frame_recycling() {
    run(&["300"]);
}

#[test]
fn a_fresh_executable_page_runs_its_own_code_after_a_child_executed_there() {
    run(&["300", "cross"]);
}
