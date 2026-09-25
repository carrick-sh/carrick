//! EL1 plan 1a signed tests: Hypervisor.framework's in-kernel GICv3 in the
//! production carrier VM.
//!
//! Run ONLY through `just test-embed el1_gic` (scripts/test-signed.sh) after
//! `scripts/build-linux-fixtures.sh`: it signs the test executable with the
//! hypervisor entitlement and runs it under `RUST_TEST_THREADS=1`. HV_DENIED
//! is a failure, never a skip.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::sync::atomic::Ordering;
use std::time::Duration;

use carrick_embed::{Carrier, EmbedError, PullPolicy, read_el1_counters, reset_el1_counters};

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

/// The directory holding the built Linux fixture `name`, for a read-only mount.
fn fixture_dir(name: &str) -> String {
    let path = common::repo_root().join(format!(
        "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/{name}"
    ));
    assert!(
        path.is_file(),
        "{}: run scripts/build-linux-fixtures.sh first",
        path.display()
    );
    path.parent()
        .expect("fixture dir")
        .to_string_lossy()
        .into_owned()
}

/// The in-kernel GIC is guest-invisible at EL0: its vCPUs report the GIC
/// system-register interface in `ID_AA64PFR0_EL1` (bits 27:24 = 1, where a
/// GIC-less VM reports 0), and Linux does not expose that field to userspace,
/// so an EL0 read in the production VM must still see 0.
#[test]
fn el1_gic_el0_id_view_hides_the_gic() {
    const FIXTURE: &str = "carrick-linux-aarch64-el0-id-view";
    let _guard = common::guest_lock();
    let dir = fixture_dir(FIXTURE);
    let carrier = carrier_or_fail();
    let result = common::run_or_fail(
        carrier
            .container(common::SMOKE_IMAGE)
            .pull_policy(PullPolicy::Missing)
            .command([format!("/p/{FIXTURE}")])
            .mount_readonly(dir, "/p")
            .run_blocking(),
    );
    let gic = carrick_runtime::carrier_gic_snapshot();
    println!("el1-gic-id-view {} {gic:?}", result.stdout_utf8().trim());
    assert!(
        result.success(),
        "exit {} signal {:?} stderr {}",
        result.exit_code,
        result.signal,
        result.stderr_utf8()
    );
    assert!(
        gic.gic,
        "the production VM carries the in-kernel GIC: {gic:?}"
    );
    assert!(gic.vcpus > 0, "no vCPU was configured for the GIC: {gic:?}");
    assert_eq!(result.stdout_utf8(), "id_aa64pfr0_gic=0\n");
}

/// Contract `kernel.el1.gic`: the guest virtual timer, armed while the guest
/// loops on EL1-served syscalls, is taken and completed at EL1 exactly once,
/// in the production VM, with no host exit of that vCPU between arming and
/// delivery other than ones the host itself caused (a host kick, or a
/// syscall forwarded for pending host work; neither carries the timer).
/// Under the GIC an untaken timer causes no exit at all (a GIC-less VM would
/// exit with VTIMER_ACTIVATED), so the claim is the EL1 delivery counted by
/// the IRQ hook plus the exit accounting of the probed vCPU.
#[test]
fn el1_gic_vtimer_reaches_el1_without_host_exits() {
    const FIXTURE: &str = "carrick-linux-aarch64-el1-vtimer-loop";
    const SYS_GETPPID: u64 = 173;
    const SYS_LSEEK: usize = 62;
    const VTIMER_INTID: usize = 27;
    const KICK_INTID: usize = 15;
    /// 1 ms of the 24 MHz virtual counter.
    const ONE_MS_TICKS: u64 = 24_000;
    let _guard = common::guest_lock();
    let dir = fixture_dir(FIXTURE);
    // Before the carrier boots: resetting forgets the live EL1 region.
    reset_el1_counters();
    carrick_runtime::el1_vtimer_probe_arm_after_syscall(SYS_GETPPID, ONE_MS_TICKS)
        .expect("the production VM has the in-kernel GIC and the EL1 kernel");
    let carrier = carrier_or_fail();
    let result = common::run_or_fail(
        carrier
            .container(common::SMOKE_IMAGE)
            .pull_policy(PullPolicy::Missing)
            .command([format!("/p/{FIXTURE}")])
            .mount_readonly(dir, "/p")
            .run_blocking(),
    );
    let report = carrick_runtime::el1_vtimer_probe_report();
    let counters = read_el1_counters().expect("EL1 counters");
    let taken = counters.irq_taken[VTIMER_INTID].load(Ordering::Relaxed);
    let kicks = counters.irq_taken[KICK_INTID].load(Ordering::Relaxed);
    let served = counters.served[SYS_LSEEK].load(Ordering::Relaxed);
    let forwarded = counters.forwarded[SYS_LSEEK].load(Ordering::Relaxed);
    println!(
        "el1-gic-vtimer {report:?} vtimer_taken={taken} kick_sgis_taken={kicks} \
         lseek served={served} forwarded={forwarded}"
    );
    assert!(
        result.success(),
        "exit {} signal {:?} stderr {}",
        result.exit_code,
        result.signal,
        result.stderr_utf8()
    );
    assert_eq!(result.stdout_utf8(), "vtimer loop ok\n");
    assert!(
        report.armed,
        "no vCPU resumed the marker syscall: {report:?}"
    );
    assert_eq!(
        taken, 1,
        "the timer interrupt was taken at EL1 exactly once"
    );
    assert!(
        report.delivered,
        "no exit of the probed vCPU saw the timer taken: {report:?}"
    );
    assert_eq!(
        report.other_exits, 0,
        "host exits between arming and delivery: {report:?}"
    );
    assert!(
        served >= 2_000_000,
        "the loop was not served at EL1: served={served} forwarded={forwarded}"
    );
}
