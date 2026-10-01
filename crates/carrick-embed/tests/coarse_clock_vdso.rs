//! Signed binding for `kernel.time.coarse-clock-vdso`: a guest reading
//! `CLOCK_MONOTONIC_COARSE` and `CLOCK_REALTIME_COARSE` (and their
//! resolution) through the vDSO causes no clock syscall at all.
//!
//! Linux serves the COARSE clocks in the vDSO without entering the kernel.
//! The EL1 kernel counts every syscall it forwards to the host by number, so
//! the guest's forwarded `clock_gettime` (113) and `clock_getres` (114)
//! counts are exactly the clock reads that cost a host service. The fixture
//! makes 10,000 vDSO reads of each COARSE clock and 10,000 vDSO resolution
//! queries of each; the contract is zero of either syscall forwarded.
//!
//! Run ONLY through `scripts/test-signed.sh carrick-embed coarse_clock_vdso`
//! after `scripts/build-linux-fixtures.sh`: it signs the test executable with
//! the hypervisor entitlement. HV_DENIED is a failure, never a skip.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::sync::atomic::Ordering;
use std::time::Duration;

use carrick_embed::{Carrier, EmbedError, PullPolicy, read_el1_counters, reset_el1_counters};

const FIXTURE: &str = "carrick-linux-aarch64-coarse-clock-vdso";
const SYS_CLOCK_GETTIME: usize = 113;
const SYS_CLOCK_GETRES: usize = 114;

fn carrier_or_fail() -> Carrier {
    for _ in 0..50 {
        match Carrier::new() {
            Ok(carrier) => return carrier,
            Err(EmbedError::Entitlement) => panic!(
                "HV_DENIED (0xfae94007): run through scripts/test-signed.sh; \
                 a bare cargo test cannot boot a guest"
            ),
            Err(EmbedError::CarrierAlreadyActive) => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(error) => panic!("carrier initialization failed: {error}"),
        }
    }
    panic!("carrier initialization timed out waiting for a prior carrier to retire");
}

#[test]
fn coarse_clock_vdso_reads_forward_no_clock_syscall() {
    let _guard = common::guest_lock();
    let path = common::repo_root().join(format!(
        "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/{FIXTURE}"
    ));
    assert!(
        path.is_file(),
        "{}: run scripts/build-linux-fixtures.sh first",
        path.display()
    );
    let dir = path
        .parent()
        .expect("fixture dir")
        .to_string_lossy()
        .into_owned();
    // Before the carrier boots: resetting forgets the live EL1 region.
    reset_el1_counters();
    let carrier = carrier_or_fail();
    let watchdog = common::Watchdog::start(Duration::from_secs(60));
    let result = common::run_or_fail(
        carrier
            .container(common::SMOKE_IMAGE)
            .pull_policy(PullPolicy::Missing)
            .command([format!("/p/{FIXTURE}")])
            .mount_readonly(dir, "/p")
            .run_blocking(),
    );
    watchdog.disarm();
    let counters = read_el1_counters().expect("the production VM carries the EL1 kernel");
    let gettime = counters.forwarded[SYS_CLOCK_GETTIME].load(Ordering::Relaxed);
    let getres = counters.forwarded[SYS_CLOCK_GETRES].load(Ordering::Relaxed);
    println!("coarse-clock-vdso forwarded clock_gettime={gettime} clock_getres={getres}");
    assert!(
        result.success(),
        "exit {} signal {:?} stderr {}",
        result.exit_code,
        result.signal,
        result.stderr_utf8()
    );
    assert_eq!(result.stdout_utf8(), "coarse vdso loop ok\n");
    assert_eq!(
        (gettime, getres),
        (0, 0),
        "COARSE vDSO reads must not enter the kernel: forwarded clock_gettime={gettime} clock_getres={getres}"
    );
}
