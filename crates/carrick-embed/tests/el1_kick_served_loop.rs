//! Signed binding of contract `kernel.vcpu.kick-el0-boundary` for kicks that
//! land inside an EL1-served syscall (Fact 9 of EL1 plan 1a).
//!
//! A stage-1 page-table drain kicks every sibling once and waits for its
//! acknowledgement with no deadline. A kick absorbed while the sibling is in
//! Carrick's EL1 syscall hook is owed to the EL0 boundary; if the served path
//! loses it, the drain never finishes. The fixture's main thread runs
//! `mmap`/first-touch/`munmap` pause cycles beside a worker that uses
//! EL1-served `lseek`, and a watchdog turns a hang into a failure.
//!
//! Run ONLY through `just test-embed el1_served_` (scripts/test-signed.sh)
//! after `scripts/build-linux-fixtures.sh`: HV_DENIED is a failure, never a
//! skip. Runs alone: a watchdog reap kills the test executable.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::sync::atomic::Ordering;
use std::time::Duration;

use carrick_embed::{Carrier, EmbedError, PullPolicy, read_el1_counters, reset_el1_counters};

const FIXTURE: &str = "carrick-linux-aarch64-el1-served-loop-kick";
const SYS_LSEEK: usize = 62;

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

/// The environment variable that turns this test executable into one CPU
/// burner process (see [`cpu_burner_process`]); its value is the parent pid.
const BURNER_ENV: &str = "CARRICK_EL1_KICK_CPU_BURNER_PARENT";

/// Separate processes that each spin one host CPU, oversubscribing the host so
/// the carrier's executor threads are preempted mid-guest. They must be other
/// processes: on the base binary, in-process spinning threads hung 2 of 45
/// subject runs, sixteen external spinners about 1 in 2. Each burner is this
/// test executable re-run as [`cpu_burner_process`]; it exits when this
/// process dies or after a hard bound, so a watchdog reap cannot orphan load.
struct CpuBurners {
    children: Vec<std::process::Child>,
}

impl CpuBurners {
    fn start() -> Self {
        let cpus = std::thread::available_parallelism().map_or(8, usize::from);
        let exe = std::env::current_exe().expect("test executable path");
        let children = (0..cpus + cpus / 2)
            .map(|_| {
                std::process::Command::new(&exe)
                    .args(["--exact", "cpu_burner_process", "--ignored", "--nocapture"])
                    .env(BURNER_ENV, std::process::id().to_string())
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .spawn()
                    .expect("spawn CPU burner")
            })
            .collect();
        Self { children }
    }
}

impl Drop for CpuBurners {
    fn drop(&mut self) {
        for child in &mut self.children {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// One CPU burner: spin until the parent test process is gone or 10 minutes
/// pass. Not a test on its own: it runs only when [`CpuBurners`] re-executes
/// this binary with [`BURNER_ENV`] set.
#[test]
#[ignore = "helper process for CpuBurners, not a test"]
fn cpu_burner_process() {
    let Some(parent) = std::env::var(BURNER_ENV)
        .ok()
        .and_then(|pid| pid.parse::<u32>().ok())
    else {
        return;
    };
    let start = std::time::Instant::now();
    while start.elapsed() < Duration::from_secs(600)
        && std::os::unix::process::parent_id() == parent
    {
        for _ in 0..100_000 {
            std::hint::spin_loop();
        }
    }
}

/// EL1 `lseek` (served, forwarded) so far in this carrier.
fn lseek_counts() -> (u64, u64) {
    read_el1_counters().map_or((0, 0), |counters| {
        (
            counters.served[SYS_LSEEK].load(Ordering::Relaxed),
            counters.forwarded[SYS_LSEEK].load(Ordering::Relaxed),
        )
    })
}

/// A carrier with the EL1 counters reset. `reset_el1_counters` also forgets
/// the EL1 region, so it must run only before the carrier boots: on a live
/// carrier it would silence every later pending-host-work mark.
fn fresh_carrier() -> Carrier {
    reset_el1_counters();
    carrier_or_fail()
}

/// Run the fixture in `mode` and assert: the pausing thread finished every
/// cycle within the watchdog, and EL1 served at least `min_served` lseeks (so
/// the served path, not the host path, was what the kicks landed in).
fn run_mode(carrier: &Carrier, mode: &str, min_served: u64) {
    let (served_before, forwarded_before) = lseek_counts();
    let fixture = common::repo_root().join(format!(
        "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/{FIXTURE}"
    ));
    assert!(
        fixture.is_file(),
        "{}: run scripts/build-linux-fixtures.sh first",
        fixture.display()
    );
    let dir = fixture.parent().expect("fixture dir").to_string_lossy();
    let watchdog = common::Watchdog::start(Duration::from_secs(90));
    let result = common::run_or_fail(
        carrier
            .container(common::SMOKE_IMAGE)
            .pull_policy(PullPolicy::Missing)
            .command([format!("/p/{FIXTURE}"), mode.to_owned()])
            .mount_readonly(dir, "/p")
            .run_blocking(),
    );
    watchdog.disarm();
    let stdout = result.stdout_utf8();
    let (served_after, forwarded_after) = lseek_counts();
    let served = served_after - served_before;
    let forwarded = forwarded_after - forwarded_before;
    println!(
        "el1-served-loop-kick mode={mode} {} el1 lseek served={served} forwarded={forwarded}",
        stdout.trim()
    );
    assert!(
        result.success(),
        "mode {mode}: exit {} signal {:?} stdout {stdout:?} stderr {}",
        result.exit_code,
        result.signal,
        result.stderr_utf8()
    );
    assert!(
        stdout.starts_with("served loop kick max_ns="),
        "mode {mode}: {stdout:?}"
    );
    assert!(
        served >= min_served,
        "mode {mode}: only {served} lseeks served in EL1 (forwarded {forwarded}); \
         the kicks did not land in the served path"
    );
}

/// A sibling looping on EL1-served `lseek` with no other work: every drain
/// completes (a kick lost in one served call is caught by the next call's
/// pending-host-work check, so this shape alone cannot hang).
#[test]
fn el1_served_loop_surfaces_kicks() {
    let _guard = common::guest_lock();
    let carrier = fresh_carrier();
    run_mode(&carrier, "loop", 10_000);
}

/// Rounds of the `burst` shape under host oversubscription.
const BURST_ROUNDS: usize = 30;

/// The sibling runs served `lseek` between pause cycles and computes in EL0
/// while one is open, with the host CPUs oversubscribed so its executor is
/// preempted mid-syscall. A kick that lands after the served path's
/// pending-host-work check must still stop the sibling at the EL0 boundary;
/// lost there, it has no later syscall to surface it and the drain waits
/// forever (the watchdog fails the run).
#[test]
fn el1_served_burst_surfaces_kicks_under_oversubscription() {
    let _guard = common::guest_lock();
    let carrier = fresh_carrier();
    let _burners = CpuBurners::start();
    for _ in 0..BURST_ROUNDS {
        run_mode(&carrier, "burst", 1_000_000);
    }
}
