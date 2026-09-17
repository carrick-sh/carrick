//! LIVE proof of the wedge ladder, on a REAL guest and a REAL debugger.
//!
//! `kernel_abort.rs` next door proves the ladder's first rung: a run that will
//! not end becomes `EmbedError::KernelAborted` carrying an in-process
//! post-mortem. That rung needs the abort latch to be CONSUMED. The state this
//! file exists for is the one where it is not: during
//! `just conformance-probes`, a carrier spun 29m45s at 104% CPU with
//! `carrick-executor-5` looping inside `continuation_services`, the latch was
//! never consumed, and the run had no bound at all.
//!
//! Two things are proved here, and the split is deliberate.
//!
//! 1. **The trigger is not reproducible on demand, and the sink is stronger
//!    than the wedge report suggested.** Parking an executor thread inside a
//!    trusted interceptor — the shape of that spin, as far as the public embed
//!    API can reach — still ends in a NAMED failure: measured here, the abort
//!    was consumed 10 ms after a 3 s budget, so the run returned
//!    `KernelAborted` and not a hang. So this asserts what is deterministic:
//!    a carrier whose only executor is parked NEVER returns `Ok` and never
//!    hangs. A test that waited for the real spin to come back would be a test
//!    that usually proves nothing.
//! 2. **The capture rung itself is exercised for real**, against this live
//!    process: `sudo -n lldb`, `thread backtrace all`, a modified-memory core,
//!    an owned 0700 directory and a manifest. That is the part that was only
//!    ever done by hand, and the part that must never return an empty pass.
//!
//! Its own test binary on purpose: the parked executor is still parked when
//! the run returns, and the capture arms a reaper that ends this process about
//! six minutes later — long after this one test has finished. Signed lane only
//! (`just test-embed a_carrier_that_cannot_consume_its_abort`);
//! `scripts/sudo/kill.sh <run-id>` reaps what the process leaves.

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use carrick_embed::testing::TestContainer;
use carrick_embed::{EmbedError, InterceptAction, InterceptedSyscall, ProcessInfo};
use carrick_image::PullPolicy;

/// The wedged container's budget. Small, because the wait under test is the
/// LADDER (budget, then the 30 s abort grace, then the capture), not the guest.
const BUDGET: Duration = Duration::from_secs(3);

/// How long the executor is parked. Longer than the whole ladder, so the
/// carrier still cannot consume its abort at every rung.
const PARK: Duration = Duration::from_secs(300);

/// How long the whole test may take. A ladder that does not finish is the
/// failure this bound catches; without it the suite would hang exactly the way
/// the spin did.
const TEST_BOUND: Duration = Duration::from_secs(600);

/// Parks the executor thread on the first guest syscall and never gives it
/// back, reproducing an executor that cannot reach a supervised wait.
#[derive(Default)]
struct ParkTheExecutor {
    parked: AtomicBool,
}

impl carrick_embed::SyscallInterceptor for ParkTheExecutor {
    fn intercept(
        &self,
        _process: &ProcessInfo<'_>,
        _call: &InterceptedSyscall<'_>,
    ) -> InterceptAction {
        if !self.parked.swap(true, Ordering::AcqRel) {
            std::thread::sleep(PARK);
        }
        InterceptAction::Continue
    }
}

#[test]
#[ignore = "attaches `sudo -n lldb` to THIS process and saves a core; run as a descendant of a \
            Claude Code session it segfaults Terminal.app (three session losses on 2026-09-15). \
            Owner-run from a separate terminal: `just test-embed wedge_capture_ladder -- --ignored`"]
fn a_carrier_that_cannot_consume_its_abort_is_captured_and_named() {
    let _guest = common::guest_lock();

    // Spend the cold-start allowance on a container that finishes, so the
    // wedged one below is bounded by exactly `BUDGET`.
    let warm = TestContainer::new(common::SMOKE_IMAGE)
        .pull_policy(PullPolicy::Missing)
        .label("wedgeladder-warmup")
        .run(["/bin/true"]);
    match warm {
        Ok(_) => {}
        Err(EmbedError::Entitlement) => panic!(
            "HV_DENIED (0xfae94007): run this through `just test-embed` \
             (scripts/test-signed.sh signs the test executable); a bare \
             `cargo test -p carrick-embed` can never boot a guest."
        ),
        Err(error) => panic!("the warm-up container must run: {error}"),
    }

    let started = Instant::now();
    let outcome = TestContainer::new(common::SMOKE_IMAGE)
        .pull_policy(PullPolicy::Missing)
        .label("wedgeladder")
        .carrier_budget(BUDGET)
        .interceptor(Arc::new(ParkTheExecutor::default()))
        .run(["/bin/true"]);
    let elapsed = started.elapsed();
    assert!(
        elapsed < TEST_BOUND,
        "the wedge ladder did not finish: {elapsed:?} elapsed"
    );

    let error = match outcome {
        Ok(result) => panic!(
            "a container whose only executor is parked cannot have completed: exit={} stdout={:?}",
            result.exit_code,
            result.stdout_utf8()
        ),
        Err(error) => error,
    };

    // Whichever rung answered, it must be a NAMED failure that says the budget
    // fired. `KernelAborted` means the in-process sink won the race to the
    // latch (the measured outcome on this box); `ProbeWedged` means it could
    // not, and the carrier was described from outside instead. A hang, an
    // `Ok`, or an unrelated error are all failures of the ladder.
    match &error {
        EmbedError::KernelAborted { reason, .. } => {
            assert!(
                reason.contains("container deadline"),
                "the abort must name the budget that fired: {reason}"
            );
        }
        EmbedError::ProbeWedged {
            label, budget_ms, ..
        } => {
            assert_eq!(label, "wedgeladder");
            assert_eq!(*budget_ms, 3_000);
        }
        other => panic!("the ladder must name the budget, got: {other}"),
    }

    capture_this_carrier_for_real();
}

/// Drive the capture rung end to end against THIS process.
///
/// The trigger above is not reproducible on demand, but the capture is the
/// part that was only ever performed by hand on the 29m45s spin, and the part
/// whose every failure mode must stay a named error rather than an empty pass.
/// So it runs here for real: a private owned directory, `sudo -n lldb`, a full
/// backtrace, a modified-memory core, and a manifest — all against a live,
/// multi-threaded carrier process.
///
/// This arms the reaper, which ends this process minutes from now. That is the
/// shipped behaviour and the reason this file holds exactly one test.
fn capture_this_carrier_for_real() {
    let pid = i32::try_from(std::process::id()).unwrap_or(-1);
    assert!(pid > 0, "host pid must fit an i32 carrier pid");
    let started = Instant::now();
    let capture = carrick_kernel::wedge_capture::capture_wedged_carrier(
        carrick_kernel::wedge_capture::WedgeCaptureRequest {
            label: "wedgeladder".to_owned(),
            pid,
            run_id: std::env::var("CARRICK_RUN_ID").ok(),
            budget_ms: 3_000,
            elapsed_ms: 33_000,
            out_root: std::path::PathBuf::from("target/postmortem"),
        },
    );
    assert!(
        capture.is_ok(),
        "the capture rung produced no evidence ({:?}); on this box that means \
         `sudo -n lldb` is unavailable — fix the debugger access, do not relax this \
         assertion, because an absent debugger is a failed capture and never a pass",
        capture.as_ref().err()
    );
    let Ok(capture) = capture else {
        return;
    };
    eprintln!(
        "WEDGE CAPTURE LIVE: {} in {:?}",
        capture.dir.display(),
        started.elapsed()
    );

    assert!(
        capture
            .dir
            .file_name()
            .is_some_and(|name| name.to_string_lossy() == format!("wedgeladder-{pid}")),
        "artifacts must be filed under the label and pid: {}",
        capture.dir.display()
    );
    assert!(capture.core.is_some(), "a complete capture has a core");
    let Some(core) = capture.core.clone() else {
        return;
    };
    for (name, artifact) in [
        ("manifest", capture.dir.join("manifest.json")),
        ("backtrace", capture.backtrace.clone()),
        ("core", core),
    ] {
        let metadata = std::fs::metadata(&artifact);
        assert!(
            metadata.is_ok(),
            "{name} {} is missing: {:?}",
            artifact.display(),
            metadata.as_ref().err()
        );
        let Ok(metadata) = metadata else {
            return;
        };
        let bytes = metadata.len();
        assert!(bytes > 0, "{name} {} is empty", artifact.display());
    }
    let backtrace = std::fs::read_to_string(&capture.backtrace);
    assert!(
        backtrace.is_ok(),
        "read backtrace: {:?}",
        backtrace.as_ref().err()
    );
    let Ok(backtrace) = backtrace else {
        return;
    };
    assert!(
        backtrace.contains("thread #"),
        "the backtrace must carry real host threads: {}",
        backtrace.chars().take(200).collect::<String>()
    );
}
