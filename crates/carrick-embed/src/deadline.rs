//! Wall-clock budgets for guest-running tests that end in a POST-MORTEM.
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
//! It is a TEST budget: a wall-clock number a human chose, so it can be wrong
//! under load, and a run that trips it has not been proved stuck. That is the
//! opposite of the always-on `ProcessGraphLiveness` invariant, whose verdict is
//! structural and load-independent. Use the budget as a backstop for shapes no
//! invariant covers yet, and read its post-mortem before believing it.

use std::sync::mpsc;
use std::time::{Duration, Instant};

use carrick_runtime::kernel::debug::{AbortReason, request_abort};

use crate::{ContainerBuilder, ContainerResult, EmbedError};

/// How long the sink is given to consume a latched deadline abort.
///
/// The latch is read by the runner at its next supervised-wait boundary, so a
/// run that is wedged in a place the runner cannot reach (image resolution,
/// preparation) will not consume it. That case gets a NAMED failure below
/// rather than an indefinite wait, because "the abort was not consumed" and
/// "the container is slow" are different diagnoses.
const ABORT_GRACE: Duration = Duration::from_secs(30);

/// Run `builder` to completion, aborting the kernel if it has not returned
/// within `budget`.
pub(crate) fn run_with_deadline(
    builder: ContainerBuilder,
    budget: Duration,
) -> Result<ContainerResult, EmbedError> {
    let (sender, receiver) = mpsc::channel();
    let started = Instant::now();
    let worker = std::thread::Builder::new()
        .name("carrick-embed-deadline".to_owned())
        .spawn(move || {
            let _ = sender.send(builder.run_blocking());
        })
        .map_err(|error| EmbedError::CarrierFailed {
            reason: format!("failed to start the deadline-bounded run: {error}"),
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
                "the deadline-bounded run thread ended without a result".to_owned(),
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
                // the unbounded wait this budget exists to remove.
                Err(mpsc::RecvTimeoutError::Timeout) => Err(EmbedError::CarrierFailed {
                    reason: format!(
                        "the container did not return {}s after its {}s deadline, and the kernel \
                         abort was never consumed: the run is wedged somewhere the runner's \
                         supervised wait does not reach (image resolution or preparation), so no \
                         post-mortem was captured",
                        ABORT_GRACE.as_secs(),
                        budget.as_secs()
                    ),
                }),
                Err(mpsc::RecvTimeoutError::Disconnected) => Err(EmbedError::ExecutePanicked(
                    "the deadline-bounded run thread ended without a result".to_owned(),
                )),
            }
        }
    }
}

fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}
