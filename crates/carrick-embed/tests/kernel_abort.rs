//! End-to-end proof of the fail-closed sink, on a REAL guest.
//!
//! The wedge this exists for is not reproducible on demand — its publisher gap
//! was closed by `f8487d23b`, and a test that waited for it to come back would
//! be a test that usually proves nothing. What IS deterministic, and what the
//! wedge actually needed, is the sink itself: a run that will not end must
//! become `EmbedError::KernelAborted` carrying a post-mortem, not a hang and
//! not a host `SIGKILL`.
//!
//! So this drives the sink with a guest that genuinely will not finish
//! (`sleep`), a wall-clock `TestContainer::deadline`, and asserts on the whole
//! chain: freeze, one in-process capture, every unpublished container job
//! completed, the typed error at the embed boundary, and the persisted
//! `post-mortem.json` + `event-ring.jsonl`.
//!
//! Its own test binary on purpose: an aborted carrier's guest threads are
//! still running when the run returns (the abort answers the WAIT, it does not
//! reap Darwin threads), and HVF allows one VM per host process. Signed lane
//! only (`just test-embed kernel_abort`); `scripts/sudo/kill.sh <run-id>` reaps
//! what the process leaves.
mod common;

use std::time::{Duration, Instant};

use carrick_embed::EmbedError;
use carrick_embed::testing::TestContainer;
use carrick_image::PullPolicy;

/// Long enough that no amount of host load makes the guest finish it, short
/// enough that the test is not itself a wait.
const GUEST_SLEEP_SECONDS: &str = "3600";

/// The budget. Generous relative to boot on a loaded shared host, because the
/// thing under test is the SINK, not the number.
const DEADLINE: Duration = Duration::from_secs(90);

/// How long the whole test may take. A sink that does not fire is the failure
/// this bound catches; without it the suite would hang exactly the way the
/// wedge did.
const TEST_BOUND: Duration = Duration::from_secs(300);

#[test]
fn a_container_that_will_not_finish_aborts_with_a_post_mortem() {
    let _guest = common::guest_lock();
    let capture_dir = tempfile::tempdir().expect("post-mortem directory");
    let started = Instant::now();

    let outcome = TestContainer::new(common::SMOKE_IMAGE)
        .pull_policy(PullPolicy::Missing)
        .deadline(DEADLINE)
        .post_mortem_dir(capture_dir.path())
        .run(["/bin/sleep", GUEST_SLEEP_SECONDS]);

    let elapsed = started.elapsed();
    assert!(
        elapsed < TEST_BOUND,
        "the sink did not fire: {elapsed:?} elapsed"
    );

    let error = match outcome {
        Ok(result) => panic!(
            "a guest sleeping {GUEST_SLEEP_SECONDS}s cannot have completed: exit={} stdout={:?}",
            result.exit_code,
            result.stdout_utf8()
        ),
        Err(EmbedError::Entitlement) => panic!(
            "HV_DENIED (0xfae94007): run this through `just test-embed` \
             (scripts/test-signed.sh signs the test executable); a bare \
             `cargo test -p carrick-embed` can never boot a guest."
        ),
        Err(error) => error,
    };

    let EmbedError::KernelAborted {
        reason,
        post_mortem,
    } = error
    else {
        panic!("expected EmbedError::KernelAborted, got: {error}");
    };
    assert!(
        reason.contains("container deadline"),
        "the error must name the judge that fired: {reason}"
    );

    // The capture is the point. A post-mortem that carries no kernel graph is
    // the failure mode this whole lane exists to remove.
    let kernel = post_mortem.kernel.as_ref().unwrap_or_else(|| {
        panic!(
            "no kernel graph in the capture: {:?}",
            post_mortem.truncated
        )
    });
    let tasks = kernel.tasks.as_ref().expect("the task table");
    assert!(
        !tasks.is_empty(),
        "a sleeping guest must appear in its own post-mortem"
    );
    assert!(
        kernel.executors.is_some(),
        "the per-executor view is what says WHERE the carrier was"
    );
    assert!(
        !post_mortem.event_ring.is_empty(),
        "the always-on event ring must reach the capture with nothing pre-armed"
    );

    // And it must be readable from disk, which is what a harness (or the
    // host-wide watchdog this replaces) actually consumes.
    let json_path = capture_dir.path().join("post-mortem.json");
    let json = std::fs::read_to_string(&json_path)
        .unwrap_or_else(|error| panic!("read {}: {error}", json_path.display()));
    let persisted: serde_json::Value = serde_json::from_str(&json).expect("post-mortem.json");
    assert_eq!(
        persisted["schema"], "carrick.kernel-post-mortem.v1",
        "{json:.400}"
    );
    assert_eq!(persisted["reason"]["kind"], "container-deadline");
    assert_eq!(
        persisted["run_id"],
        common::run_id(),
        "the capture must name the run scripts/sudo/kill.sh reaps"
    );

    let ring_path = capture_dir.path().join("event-ring.jsonl");
    let ring = std::fs::read_to_string(&ring_path)
        .unwrap_or_else(|error| panic!("read {}: {error}", ring_path.display()));
    assert_eq!(
        ring.lines().count(),
        post_mortem.event_ring.len(),
        "every ring record is one line"
    );
}
