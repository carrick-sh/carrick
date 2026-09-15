//! The CARRIER BUDGET: a wall-clock bound on one embedded run that ends in a
//! POST-MORTEM, and — when the carrier cannot even reach the post-mortem — in
//! an external capture of the wedged process.
//!
//! # Why not a host `SIGKILL`
//!
//! The signed lane's previous bound was a thread the harness deliberately did
//! not join (`crates/carrick-embed/tests/scheduler_race.rs`), plus a host-wide
//! shell watchdog that reaped a frozen carrier three minutes later. Both turn a
//! wedge into an exit code: `rc=137` and no kernel graph, no run queue, no
//! event ring — the 2026-09-07 exit wedge was diagnosed only because someone
//! separately attached `lldb`.
//!
//! A budget here instead triggers the ONE fail-closed sink. The runtime freezes
//! its scheduler, captures a `PostMortem` in process, completes every
//! unpublished container job, and the run returns
//! [`EmbedError::KernelAborted`] with that capture attached. The test failure
//! and the diagnosis arrive together.
//!
//! # What this budget is and is not
//!
//! It is a TEST budget: a wall-clock number, so it can be wrong under load, and
//! a run that trips it has not been proved stuck. That is the opposite of the
//! always-on `ProcessGraphLiveness` invariant, whose verdict is structural and
//! load-independent. Use the budget as a backstop for shapes no invariant
//! covers yet, and read its post-mortem before believing it.
//!
//! It ships ON. A bound nothing arms is not a bound: `TestContainer::deadline`
//! existed, defaulted to `None`, and no probe ever called it, so the
//! `forkstackstorm` carrier spun 29m45s at 104% CPU inside
//! `just conformance-probes` and ended only when a human attached `lldb`.
//! `CARRICK_PROBE_CARRIER_BUDGET_MS=0` is the exact hatch for a bisection run.

use std::path::PathBuf;
use std::sync::OnceLock;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use carrick_runtime::deadlock_watchdog::{self, DeadlockWindow};
use carrick_runtime::kernel::debug::{AbortReason, request_abort};
use carrick_runtime::wedge_capture::{WedgeCaptureRequest, capture_wedged_carrier};

use crate::{ContainerBuilder, ContainerResult, EmbedError};

/// How long the sink is given to consume a latched deadline abort.
///
/// The latch is read by the runner at its next supervised-wait boundary, so a
/// run that is wedged in a place the runner cannot reach (a spinning executor,
/// image resolution, preparation) will not consume it. That case escalates to
/// an external capture below, because "the abort was not consumed" and "the
/// container is slow" are different diagnoses.
const ABORT_GRACE: Duration = Duration::from_secs(30);

/// How many budgets of total carrier silence count as a carrier-wide stall.
const CARRIER_STALL_MULTIPLE: u32 = 3;

/// The operator hatch. `0` disables the budget exactly; any other value
/// replaces it for that run. One spelling, read once.
pub(crate) const CARRIER_BUDGET_ENV: &str = "CARRICK_PROBE_CARRIER_BUDGET_MS";

/// The default budget for one container, in milliseconds.
///
/// Measured, not chosen: one green `just conformance-probes` on this Mac
/// (2026-09-15, 902 generic probe runs across both libcs) reported
/// p50 117 ms, p90 519 ms, p95 1347 ms, p99 4650 ms, p99.5 5379 ms, with two
/// deliberately slow probes above it (`futexforkrequeue` 14.4 s and
/// `mtidlesleep` 20.1 s, both carried by the per-probe override table in
/// `carrick-conformance-next`). 60 s is ~11x the p99.5 of that population, so
/// scheduling noise cannot reach it, while still being three orders of
/// magnitude below the 29m45s wedge this budget exists to cut.
pub const DEFAULT_CARRIER_BUDGET_MS: u64 = 60_000;

/// Extra time granted to the FIRST container in a host process.
///
/// The first container pays for image resolution and a cold guest: that is why
/// a default 10 s `ExitBudget` aborted the probe lane's first case (see
/// `TestContainer::exit_budget`). The measured first rows of a warm store cost
/// 240-263 ms, but a cold store pulls an image on that same row, so the
/// allowance is sized for the pull rather than for the warm case.
pub const COLD_START_ALLOWANCE_MS: u64 = 120_000;

fn carrier_budget_override_ms() -> Option<u64> {
    static CELL: OnceLock<Option<u64>> = OnceLock::new();
    *CELL.get_or_init(|| {
        std::env::var(CARRIER_BUDGET_ENV)
            .ok()
            .and_then(|raw| raw.trim().parse::<u64>().ok())
    })
}

/// Resolve the budget one run is bounded by.
///
/// `override_ms` is the operator hatch as read from the environment: `None`
/// means absent, `Some(0)` is the exact disable, and any other value replaces
/// the container's own request. Kept pure so both the hatch and the cold-start
/// allowance are provable without touching the environment.
pub(crate) fn resolve_carrier_budget(
    override_ms: Option<u64>,
    requested: Option<Duration>,
    first_in_process: bool,
) -> Option<Duration> {
    let base = match override_ms {
        Some(0) => return None,
        Some(ms) => Duration::from_millis(ms),
        None => requested.unwrap_or(Duration::from_millis(DEFAULT_CARRIER_BUDGET_MS)),
    };
    Some(if first_in_process {
        base + Duration::from_millis(COLD_START_ALLOWANCE_MS)
    } else {
        base
    })
}

/// The budget a container gets, hatch and cold-start allowance applied.
///
/// Public so the harness that names per-probe budgets can prove its own policy
/// agrees with the resolution that will actually be applied; a second
/// computation of the same number is a second answer waiting to drift.
pub fn effective_carrier_budget(
    requested: Option<Duration>,
    first_in_process: bool,
) -> Option<Duration> {
    resolve_carrier_budget(carrier_budget_override_ms(), requested, first_in_process)
}

#[cfg(test)]
thread_local! {
    /// The budget the last run on this thread lowered to. Test-visible so the
    /// audit entry point cannot silently stop being bounded again.
    static LAST_RUN_PLAN: std::cell::Cell<Option<Option<Duration>>> =
        const { std::cell::Cell::new(None) };
}

#[cfg(test)]
pub(crate) fn record_run_plan(plan: Option<Duration>) {
    LAST_RUN_PLAN.with(|slot| slot.set(Some(plan)));
}

#[cfg(test)]
pub(crate) fn last_run_plan() -> Option<Option<Duration>> {
    LAST_RUN_PLAN.with(std::cell::Cell::get)
}

#[cfg(test)]
pub(crate) fn forget_last_run_plan() {
    LAST_RUN_PLAN.with(|slot| slot.set(None));
}

/// Where a wedge capture's artifacts land, relative to the process's working
/// directory — the repository root under `scripts/test-signed.sh`.
pub(crate) fn wedge_capture_root() -> PathBuf {
    PathBuf::from("target/postmortem")
}

/// Run `builder` to completion, aborting the kernel if it has not returned
/// within `budget`, and capturing the carrier externally if even the abort
/// cannot be consumed.
pub(crate) fn run_with_carrier_budget(
    builder: ContainerBuilder,
    budget: Duration,
    label: &str,
) -> Result<ContainerResult, EmbedError> {
    // The budget bounds ONE run; the watchdog bounds the whole carrier, and it
    // is the only thing that sees a stall outside a run (teardown, the gap
    // between containers). Its window is a multiple of the budget so a guest
    // that legitimately sleeps through a whole run — `mtidlesleep` sleeps 20 s
    // with no syscalls — never trips it.
    if let Some(window) = DeadlockWindow::new(budget * CARRIER_STALL_MULTIPLE) {
        deadlock_watchdog::arm(window);
    }

    let (sender, receiver) = mpsc::channel();
    let started = Instant::now();
    let worker = std::thread::Builder::new()
        .name("carrick-embed-carrier-budget".to_owned())
        .spawn(move || {
            let _ = sender.send(builder.run_blocking());
        })
        .map_err(|error| EmbedError::CarrierFailed {
            reason: format!("failed to start the budget-bounded run: {error}"),
        })?;

    match receiver.recv_timeout(budget) {
        Ok(result) => {
            // Joining is safe here: the worker has already sent, so it is at
            // its last statement.
            let _ = worker.join();
            result
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            let _ = worker.join();
            Err(EmbedError::ExecutePanicked(
                "the budget-bounded run thread ended without a result".to_owned(),
            ))
        }
        Err(mpsc::RecvTimeoutError::Timeout) => {
            let elapsed = started.elapsed();
            request_abort(AbortReason::ContainerDeadline {
                elapsed_ms: millis(elapsed),
                budget_ms: millis(budget),
            });
            match receiver.recv_timeout(ABORT_GRACE) {
                Ok(result) => {
                    let _ = worker.join();
                    result
                }
                // The worker is deliberately NOT joined here: it is still
                // inside the carrier, and joining it would reproduce exactly
                // the unbounded wait this budget exists to remove. The wedged
                // thread is instead described from outside, by a debugger, and
                // the carrier is reaped behind the returned error.
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    Err(wedged(label, budget, started.elapsed()))
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => Err(EmbedError::ExecutePanicked(
                    "the budget-bounded run thread ended without a result".to_owned(),
                )),
            }
        }
    }
}

/// The abort latch was never consumed: capture the carrier from outside and
/// report where the artifacts are. Both outcomes are named failures; neither
/// is ever an empty pass.
fn wedged(label: &str, budget: Duration, elapsed: Duration) -> EmbedError {
    let pid = i32::try_from(std::process::id()).unwrap_or(-1);
    let request = WedgeCaptureRequest {
        label: label.to_owned(),
        pid,
        run_id: std::env::var("CARRICK_RUN_ID").ok(),
        budget_ms: millis(budget),
        elapsed_ms: millis(elapsed),
        out_root: wedge_capture_root(),
    };
    match capture_wedged_carrier(request) {
        Ok(capture) => {
            // Printed as well as returned: the carrier is reaped behind this
            // error, so the artifact path has to be in the log even if the
            // process dies before the failure is formatted.
            eprintln!(
                "PROBE WEDGED {label}: budget {}ms exceeded and the kernel abort was never \
                 consumed; artifacts in {}",
                millis(budget),
                capture.dir.display()
            );
            EmbedError::ProbeWedged {
                label: label.to_owned(),
                budget_ms: millis(budget),
                elapsed_ms: millis(elapsed),
                artifacts: capture.dir,
            }
        }
        Err(error) => {
            let artifacts = error.directory().map(std::path::Path::to_path_buf);
            eprintln!("PROBE WEDGE CAPTURE FAILED {label}: {error}");
            EmbedError::ProbeWedgeCaptureFailed {
                label: label.to_owned(),
                reason: error.to_string(),
                artifacts,
            }
        }
    }
}

fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_absent_hatch_leaves_the_measured_default() {
        assert_eq!(
            resolve_carrier_budget(None, None, false),
            Some(Duration::from_millis(DEFAULT_CARRIER_BUDGET_MS))
        );
    }

    #[test]
    fn the_cold_start_allowance_is_added_once_to_whatever_budget_applies() {
        let requested = Duration::from_millis(7_000);
        assert_eq!(
            resolve_carrier_budget(None, Some(requested), true),
            Some(requested + Duration::from_millis(COLD_START_ALLOWANCE_MS))
        );
        assert_eq!(
            resolve_carrier_budget(Some(250), None, true),
            Some(Duration::from_millis(250 + COLD_START_ALLOWANCE_MS))
        );
    }
}
