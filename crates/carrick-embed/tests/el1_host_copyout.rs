//! Signed contract `kernel.el1.anonymous-reservations.host-copyout`.
//!
//! Run ONLY through `just test-embed` (scripts/test-signed.sh).
//!
//! With the EL1 reservation root admitted (the default), a fresh private
//! anonymous mapping's untouched pages have no frame. A host copyout into
//! them (`read`, `pread64`, `recvfrom`) must be served by the same root
//! grant an EL0 first touch gets, and a host read of them (`write`) sees
//! zero; both used to return EFAULT. The fixture also races a copyout
//! against an EL0 first touch of the same page from another thread: one
//! frame backs the page, so neither store is lost.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use carrick_embed::ContainerBuilder;
use carrick_image::PullPolicy;

#[test]
fn el1_host_copyout_into_and_out_of_untouched_reserved_memory() {
    let _guard = common::guest_lock();
    let watchdog = common::Watchdog::start(std::time::Duration::from_secs(120));
    let result = common::run_or_fail(
        ContainerBuilder::from_image(common::SMOKE_IMAGE)
            .pull_policy(PullPolicy::Missing)
            .command(["/opt/carrick/copyout"])
            .vfs_mount("/opt/carrick", Box::new(common::copyout_vfs()))
            .run_blocking(),
    );
    watchdog.disarm();
    assert!(
        result.success() && result.stdout_utf8().trim() == "copyout_ok",
        "exit_code={} stdout={:?} stderr={}",
        result.exit_code,
        result.stdout_utf8(),
        result.stderr_utf8()
    );
}

#[test]
fn el1_host_buffers_follow_reused_mapping_in_two_live_processes() {
    let _guard = common::guest_lock();
    let watchdog = common::Watchdog::start(std::time::Duration::from_secs(30));
    let result = common::run_or_fail(
        ContainerBuilder::from_image(common::SMOKE_IMAGE)
            .pull_policy(PullPolicy::Missing)
            .command(["/opt/carrick/copyout", "reuse"])
            .vfs_mount("/opt/carrick", Box::new(common::copyout_vfs()))
            .run_blocking(),
    );
    watchdog.disarm();
    assert!(
        result.success() && result.stdout_utf8().trim() == "copyout_reuse_ok",
        "exit_code={} stdout={:?} stderr={}",
        result.exit_code,
        result.stdout_utf8(),
        result.stderr_utf8()
    );
}
