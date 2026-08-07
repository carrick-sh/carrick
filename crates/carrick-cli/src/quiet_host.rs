//! The settle-and-refuse quiet-host preflight behind `carrick trace
//! --preflight-quiet-host`.
//!
//! **Why this is Rust and not shell.** Every timed capture in this tree has so
//! far been fronted by a bash driver whose `preflight()` was the single most
//! valuable thing it did — the deleted attr36 driver
//! (`git show 1cb06de6^:scripts/perf/live-arena-attribution-capture.sh`) spent
//! 20 of its ~100 lines on it, and its value was not the measurement but the
//! REFUSAL: a dirty host aborted rather than producing a number that would then
//! be quoted forever. Moving it into the command that takes the measurement
//! means the receipt travels with the capture instead of with a log file
//! somebody has to be told to read, and it shrinks the shell driver to the arm
//! loop it should always have been.
//!
//! **What "quiet" means here, and why each term.**
//!
//! * **Settled load.** A one-minute load average below
//!   [`MAX_LOADAVG_MILLI`] — the deleted driver's `int($2) < 4` — polled until
//!   it settles, because the usual dirty-host case is the tail of a previous
//!   arm, which drains on its own. Failing to settle inside
//!   [`MAX_SETTLE_SECONDS`] is a refusal, not a longer wait.
//! * **No `yes` processes.** This tree's load generator is `yes > /dev/null`.
//!   A leftover one is invisible in a wall clock and fatal to a CPU-ns figure.
//! * **No `carrick:` processes.** A stray guest from an earlier run competes
//!   for the same P-cores and, worse, would be counted by an instrument scoped
//!   on `proc:::create` progeny if it forks into the tree.
//!
//! **On shelling out to `pgrep`/`ps`.** The load average is read through
//! `libc::getloadavg`, but the process-table screens run the host tools. The
//! alternative is a `sysctl(KERN_PROC_ALL)` walk of `kinfo_proc`, which is
//! per-OS `unsafe` struct decoding for a check whose whole job is to be
//! obviously correct — and Rust still owns what matters: the invocation, the
//! parse, the typed receipt, and the refusal. A tool that fails to run at all
//! is a refusal too; this preflight has no silent-pass path.

use std::process::Command;
use std::time::Duration;

use anyhow::{Context, Result, bail};

/// One-minute load average ceiling, in thousandths.
///
/// 4.000 is the deleted driver's threshold, kept rather than re-derived: it is
/// the number every published capture in `docs/perf-results/` was taken under,
/// so changing it would silently make new captures incomparable with the
/// archive.
const MAX_LOADAVG_MILLI: u64 = 4_000;
const SETTLE_POLL_SECONDS: u64 = 5;
/// 15 minutes, the deleted driver's `seq 1 180` × 5 s.
const MAX_SETTLE_SECONDS: u64 = 900;

/// The load generator this tree uses, matched by process NAME (`pgrep -x`).
const LOAD_GENERATOR: &str = "yes";
/// carrick rewrites a guest's argv0 to `carrick:<run-id>: <name>`
/// (`proctitle.rs`), which is why `scripts/sudo/kill.sh` matches this token
/// rather than `carrick run`. The trace front-end's own title is NOT rewritten,
/// so this screen never counts the process running it.
const GUEST_PROCTITLE_TOKEN: &str = "carrick:";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct QuietHostSample {
    pub(crate) loadavg1_milli: u64,
    pub(crate) load_generators: u64,
    pub(crate) carrick_processes: u64,
}

/// What an accepted host looked like at the instant the capture was allowed to
/// start. Written into the capture's own stream header and carried forward into
/// the ledger, so an artifact can be asked what it was measured on.
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct QuietHostReceipt {
    pub(crate) settle_s: u64,
    pub(crate) loadavg1_milli: u64,
}

impl QuietHostReceipt {
    /// The header fields, in the fixed order a profile header renders them.
    ///
    /// The accepted counts are not fields because they are always zero by
    /// construction — a nonzero one is a refusal, so recording it would be
    /// recording a number that can never appear. What varies, and therefore
    /// what is worth carrying, is how long the host took to settle and what it
    /// settled to.
    pub(crate) fn header_fields(&self) -> String {
        format!(
            "|preflight=quiet-host|preflight_settle_s={}|preflight_loadavg1_milli={}",
            self.settle_s, self.loadavg1_milli
        )
    }

    pub(crate) fn from_header_fields(settle_s: u64, loadavg1_milli: u64) -> Result<Self> {
        let receipt = Self {
            settle_s,
            loadavg1_milli,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    /// A receipt is evidence, so it is re-checked wherever it is read back: a
    /// deserialized one never went through the constructor.
    pub(crate) fn validate(&self) -> Result<()> {
        if self.loadavg1_milli >= MAX_LOADAVG_MILLI {
            bail!(
                "quiet-host receipt records a settled load average of {} milli, at or above the {MAX_LOADAVG_MILLI} ceiling it claims to have cleared",
                self.loadavg1_milli
            );
        }
        if self.settle_s > MAX_SETTLE_SECONDS {
            bail!(
                "quiet-host receipt records {}s of settling, beyond the {MAX_SETTLE_SECONDS}s ceiling",
                self.settle_s
            );
        }
        Ok(())
    }
}

/// Settle, then refuse. The public entry point.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) fn preflight_quiet_host() -> Result<QuietHostReceipt> {
    settle_and_refuse(sample_host, |seconds| {
        std::thread::sleep(Duration::from_secs(seconds))
    })
}

/// The decision, with the host reads injected so the refusal paths are
/// testable without a dirty machine.
fn settle_and_refuse(
    mut sample: impl FnMut() -> Result<QuietHostSample>,
    mut wait: impl FnMut(u64),
) -> Result<QuietHostReceipt> {
    let mut settle_s = 0_u64;
    loop {
        let observed = sample().context("sample host quiescence")?;
        if observed.loadavg1_milli < MAX_LOADAVG_MILLI {
            // Only now are the process screens meaningful: the usual dirty
            // host is the tail of a previous arm, and the tail drains.
            if observed.load_generators != 0 || observed.carrick_processes != 0 {
                bail!(
                    "host is not quiet: {} `{LOAD_GENERATOR}` load generator(s) and {} `{GUEST_PROCTITLE_TOKEN}` process(es) are still running. Reap them (scripts/sudo/kill.sh <run-id>) before capturing; a contended host produces a CPU-ns figure that reads as real",
                    observed.load_generators,
                    observed.carrick_processes
                );
            }
            return QuietHostReceipt::from_header_fields(settle_s, observed.loadavg1_milli);
        }
        if settle_s >= MAX_SETTLE_SECONDS {
            bail!(
                "host load average did not settle below {MAX_LOADAVG_MILLI} milli within {MAX_SETTLE_SECONDS}s (last reading {} milli); refusing to capture rather than measuring a busy host",
                observed.loadavg1_milli
            );
        }
        wait(SETTLE_POLL_SECONDS);
        settle_s = settle_s.saturating_add(SETTLE_POLL_SECONDS);
    }
}

fn sample_host() -> Result<QuietHostSample> {
    Ok(QuietHostSample {
        loadavg1_milli: loadavg1_milli()?,
        load_generators: count_named_processes(LOAD_GENERATOR)?,
        carrick_processes: count_proctitle_processes(GUEST_PROCTITLE_TOKEN)?,
    })
}

fn loadavg1_milli() -> Result<u64> {
    let mut averages = [0.0_f64; 3];
    // SAFETY: `getloadavg` fills at most `nelem` doubles of the buffer it is
    // handed; the buffer is three doubles and three are requested.
    let filled = unsafe { libc::getloadavg(averages.as_mut_ptr(), 3) };
    if filled < 1 {
        bail!("getloadavg() reported no load averages; the quiet-host preflight cannot pass blind");
    }
    let one_minute = averages[0];
    if !one_minute.is_finite() || one_minute < 0.0 {
        bail!("getloadavg() returned a nonsensical one-minute average {one_minute}");
    }
    Ok((one_minute * 1_000.0) as u64)
}

/// `pgrep -x <name>`: an exit status of 1 means "no match", which is the answer
/// this preflight wants most of the time. Anything else is a refusal — a
/// preflight that cannot run its own screen has not screened anything.
fn count_named_processes(name: &str) -> Result<u64> {
    let output = Command::new("pgrep")
        .arg("-x")
        .arg(name)
        .output()
        .with_context(|| format!("run pgrep -x {name} for the quiet-host preflight"))?;
    match output.status.code() {
        Some(0) => Ok(count_nonempty_lines(&output.stdout)),
        Some(1) => Ok(0),
        other => bail!(
            "pgrep -x {name} failed with status {other:?}; the quiet-host preflight cannot screen blind"
        ),
    }
}

fn count_proctitle_processes(token: &str) -> Result<u64> {
    let output = Command::new("ps")
        .args(["-axww", "-o", "command="])
        .output()
        .context("run ps for the quiet-host preflight")?;
    if !output.status.success() {
        bail!(
            "ps failed with status {:?}; the quiet-host preflight cannot screen blind",
            output.status.code()
        );
    }
    let listing = String::from_utf8_lossy(&output.stdout);
    Ok(listing
        .lines()
        .filter(|line| line.contains(token))
        .count()
        .try_into()
        .unwrap_or(u64::MAX))
}

fn count_nonempty_lines(bytes: &[u8]) -> u64 {
    String::from_utf8_lossy(bytes)
        .lines()
        .filter(|line| !line.trim().is_empty())
        .count()
        .try_into()
        .unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    fn quiet(loadavg1_milli: u64) -> QuietHostSample {
        QuietHostSample {
            loadavg1_milli,
            load_generators: 0,
            carrick_processes: 0,
        }
    }

    fn run(samples: Vec<QuietHostSample>) -> (Result<QuietHostReceipt>, u64) {
        let waited = RefCell::new(0_u64);
        let remaining = RefCell::new(samples.into_iter());
        let outcome = settle_and_refuse(
            || {
                remaining.borrow_mut().next().ok_or_else(|| {
                    anyhow::anyhow!("the preflight sampled more often than expected")
                })
            },
            |seconds| *waited.borrow_mut() += seconds,
        );
        let waited = *waited.borrow();
        (outcome, waited)
    }

    #[test]
    fn a_quiet_host_is_accepted_immediately_and_receipts_what_it_saw() {
        let (outcome, waited) = run(vec![quiet(420)]);
        let receipt = outcome.expect("a quiet host must be accepted");
        assert_eq!(waited, 0);
        assert_eq!(
            receipt,
            QuietHostReceipt {
                settle_s: 0,
                loadavg1_milli: 420
            }
        );
        assert_eq!(
            receipt.header_fields(),
            "|preflight=quiet-host|preflight_settle_s=0|preflight_loadavg1_milli=420"
        );
    }

    #[test]
    fn a_busy_host_is_waited_out_and_the_settling_time_is_receipted() {
        let (outcome, waited) = run(vec![quiet(9_000), quiet(5_000), quiet(1_200)]);
        let receipt = outcome.expect("a host that settles must be accepted");
        assert_eq!(waited, 2 * SETTLE_POLL_SECONDS);
        assert_eq!(receipt.settle_s, 2 * SETTLE_POLL_SECONDS);
        assert_eq!(receipt.loadavg1_milli, 1_200);
    }

    /// The refusal that matters: the deleted shell driver existed so that a
    /// dirty host ABORTED instead of producing a number.
    #[test]
    fn a_dirty_host_is_refused_by_name_rather_than_measured() {
        for (sample, needle) in [
            (
                QuietHostSample {
                    loadavg1_milli: 100,
                    load_generators: 2,
                    carrick_processes: 0,
                },
                "load generator",
            ),
            (
                QuietHostSample {
                    loadavg1_milli: 100,
                    load_generators: 0,
                    carrick_processes: 1,
                },
                "carrick:",
            ),
        ] {
            let (outcome, _) = run(vec![sample]);
            let message = format!("{:#}", outcome.expect_err("a dirty host must be refused"));
            assert!(message.contains(needle), "unnamed refusal: {message}");
        }
    }

    #[test]
    fn a_host_that_never_settles_is_refused_instead_of_waited_on_forever() {
        let polls = (MAX_SETTLE_SECONDS / SETTLE_POLL_SECONDS) + 1;
        let (outcome, waited) = run(vec![quiet(40_000); polls as usize]);
        let message = format!("{:#}", outcome.expect_err("a busy host must be refused"));
        assert!(message.contains("did not settle"), "{message}");
        assert_eq!(waited, MAX_SETTLE_SECONDS);
    }

    /// A receipt is evidence, so it is re-checked when read back: a header
    /// claiming a settled host at a load the ceiling would have refused is a
    /// forged or drifted receipt, not a quiet host.
    #[test]
    fn a_receipt_that_contradicts_its_own_ceiling_is_refused_on_read() {
        assert!(QuietHostReceipt::from_header_fields(0, MAX_LOADAVG_MILLI).is_err());
        assert!(QuietHostReceipt::from_header_fields(MAX_SETTLE_SECONDS + 5, 100).is_err());
        assert!(QuietHostReceipt::from_header_fields(MAX_SETTLE_SECONDS, 3_999).is_ok());
    }
}
