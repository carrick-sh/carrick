//! The one fail-closed sink: `KernelAbort` and its in-process [`PostMortem`].
//!
//! # Why this exists
//!
//! Before this module a misbehaving run had three endings, all slow: it hung
//! until a human attached `lldb` and ran `carrick debug hvpatch-kernel`; it
//! died with a carrier `abort()` that left a core and no kernel-graph view; or
//! it delivered a guest signal the guest reported as its own bug. The exit
//! wedge of 2026-09-07 (`tasks: []`, one zombie pid 1 with no parent, every
//! executor parked in `RunQueue::take_row`, `ContainerJobGroup::join` waiting
//! forever) was diagnosed only because a host-wide shell watchdog took a
//! backtrace three minutes later. That is the wrong instrument: the kernel knew
//! the process graph was empty and a job was unpublished the instant it
//! happened.
//!
//! Every judge — the always-on `ProcessGraphLiveness` runner invariant, a test
//! deadline, an exit budget, `carrick debug abort` — reports here, and this
//! module answers with ONE shape: a captured [`PostMortem`] and an
//! `EmbedError::KernelAborted`. There is no second sink and no panic path
//! beside it.
//!
//! # What a capture must never do
//!
//! Refuse itself. [`Kernel::snapshot`] is a served projection, so it fails
//! closed on a violated invariant — correct for a debugger, fatal for a
//! post-mortem. Two wedged carriers (`target/perf/wedges/conf-36312-c00`) were
//! captured only as the single line "mapping MappingId(22) names mm MmId(1),
//! which is not in the snapshot", with every table discarded. The capture here
//! uses [`Kernel::forensic_snapshot`], which records that dangling row as a
//! [`SnapshotFinding`] BESIDE the tables — the leak is reported, not hidden,
//! and never at the price of the graph.
//!
//! [`Kernel::snapshot`]: crate::kernel::Kernel::snapshot
//! [`Kernel::forensic_snapshot`]: crate::kernel::Kernel::forensic_snapshot
//! [`SnapshotFinding`]: crate::kernel::SnapshotFinding

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use super::dto::{KernelDebugSnapshot, KernelDebugTable};
use crate::kernel::core::Kernel;

pub const POST_MORTEM_SCHEMA: &str = "carrick.kernel-post-mortem.v1";

/// Process-wide capture directory installed by `ContainerBuilder::post_mortem_dir`
/// or `carrick run --post-mortem-dir`.
static INSTALLED_DIR: std::sync::OnceLock<parking_lot::Mutex<Option<PathBuf>>> =
    std::sync::OnceLock::new();

/// A pending externally-requested abort (`carrick debug abort --run-id`).
///
/// The debug server cannot itself complete the container's jobs — it holds the
/// kernel, not the runner — so it LATCHES the reason here and the runner's
/// supervised wait picks it up at its next poll and runs the one sink. That
/// keeps exactly one capture per abort: the request is a trigger, not a second
/// capture path.
static ABORT_REQUEST: std::sync::OnceLock<parking_lot::Mutex<Option<AbortReason>>> =
    std::sync::OnceLock::new();

/// Latch an abort for the runner to execute at its next boundary.
pub fn request_abort(reason: AbortReason) {
    *ABORT_REQUEST
        .get_or_init(|| parking_lot::Mutex::new(None))
        .lock() = Some(reason);
}

/// Take a latched abort request, if one is pending. Consuming it means one
/// request produces exactly one abort.
pub fn take_abort_request() -> Option<AbortReason> {
    ABORT_REQUEST.get().and_then(|slot| slot.lock().take())
}

/// Directory a run writes `post-mortem.json` + `event-ring.jsonl` into.
/// `ContainerBuilder::post_mortem_dir` and the CLI's `--post-mortem-dir` set
/// it; an operator can set it directly for a run they did not build.
pub const POST_MORTEM_DIR_ENV: &str = "CARRICK_POSTMORTEM_DIR";

/// How long the whole capture may take. A post-mortem competes with nothing —
/// the carrier is already going to fail — but it must not itself become the
/// hang it was built to diagnose.
pub const CAPTURE_DEADLINE: Duration = Duration::from_secs(2);

/// Ring records a capture carries. The ring holds 8192; taking all of them
/// keeps the capture whole where `carrick debug executor-receipt` truncates.
const EVENT_RING_RECORDS: usize = 8192;

/// Why the kernel was aborted. Typed, because the reader's next question is
/// always "which invariant, on what evidence", and a string cannot be joined
/// to the tables below it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum AbortReason {
    /// The always-on runner invariant: no live Linux task can ever reach a
    /// safe point again, yet a container process job has no published result.
    /// `zombies` names the unreapable remains — a pid-1 zombie with no parent
    /// is the exit-wedge signature, because init exiting ends the pid
    /// namespace and nobody is left to reap it.
    ProcessGraphLiveness {
        unpublished_jobs: usize,
        live_tasks: usize,
        live_threads: usize,
        runnable_rows: usize,
        zombies: Vec<ZombieSummary>,
        /// How long the predicate held unchanged before the verdict. This is
        /// confirmation latency, not a timeout: the verdict is structural.
        confirmed_after_ms: u64,
    },
    /// `carrick debug abort --run-id <id>`; replaces the shell watchdog's
    /// lldb step.
    DebugRequest { run_id: String },
    /// `TestContainer::deadline` — a wall-clock test budget that ends in a
    /// post-mortem instead of a host `SIGKILL`.
    ContainerDeadline { elapsed_ms: u64, budget_ms: u64 },
    /// A per-process `ExitBudget` timer armed at a matched event and not
    /// disarmed by an `exit_settled`.
    ExitBudget {
        selector: String,
        task: Option<i32>,
        budget_ms: u64,
    },
    /// A `KernelAuditor` verdict (lane A's judgement surface).
    Auditor { invariant: String, detail: String },
}

impl AbortReason {
    /// One line for a `Display`/log/error message.
    pub fn summary(&self) -> String {
        match self {
            Self::ProcessGraphLiveness {
                unpublished_jobs,
                live_tasks,
                live_threads,
                runnable_rows,
                zombies,
                confirmed_after_ms,
            } => {
                let named = zombies
                    .iter()
                    .map(ZombieSummary::describe)
                    .collect::<Vec<_>>()
                    .join(", ");
                let named = if named.is_empty() {
                    "no zombies".to_owned()
                } else {
                    named
                };
                format!(
                    "process-graph liveness: {unpublished_jobs} container job(s) unpublished with \
                     {live_tasks} live task(s), {live_threads} live thread(s) and {runnable_rows} \
                     runnable row(s) for {confirmed_after_ms}ms; {named}"
                )
            }
            Self::DebugRequest { run_id } => {
                format!("kernel abort requested for run {run_id}")
            }
            Self::ContainerDeadline {
                elapsed_ms,
                budget_ms,
            } => format!("container deadline: {elapsed_ms}ms elapsed of a {budget_ms}ms budget"),
            Self::ExitBudget {
                selector,
                task,
                budget_ms,
            } => format!(
                "exit budget: task {} selected by {selector} did not exit within {budget_ms}ms",
                task.map_or_else(|| "?".to_owned(), |id| id.to_string())
            ),
            Self::Auditor { invariant, detail } => format!("auditor {invariant}: {detail}"),
        }
    }
}

/// A zombie the abort names, in the terms `wait(2)` uses.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ZombieSummary {
    pub id: i32,
    pub serial: u64,
    pub parent: Option<i32>,
}

impl ZombieSummary {
    fn describe(&self) -> String {
        let parent = match self.parent {
            Some(parent) => parent.to_string(),
            None => "none".to_owned(),
        };
        // pid 1 with no parent is the exit-wedge signature, and the reader
        // should not have to know that: say so in the row.
        if self.id == 1 && self.parent.is_none() {
            "zombie pid 1 (init) with no parent — the pid namespace has no reaper left".to_owned()
        } else {
            format!("zombie pid {} (parent {parent})", self.id)
        }
    }
}

/// One captured table that did not fit the deadline. Never a silent omission.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Truncated {
    pub section: String,
    pub reason: String,
}

/// Everything the kernel knew at the moment it was aborted.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PostMortem {
    pub schema: String,
    pub run_id: Option<String>,
    pub captured_at_unix_ms: u64,
    pub reason: AbortReason,
    /// The kernel graph, in the same projection `carrick debug hvpatch-kernel`
    /// serves — so the two views can never disagree about shape.
    pub kernel: Option<KernelDebugSnapshot>,
    /// What is WRONG with that graph. A dangling alias-registry row lands
    /// here instead of destroying the capture.
    pub findings: Vec<String>,
    /// The always-on event ring, oldest to newest. A slot the reader could
    /// not decode is kept as its named read error.
    pub event_ring: Vec<EventRingRecord>,
    pub truncated: Vec<Truncated>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EventRingRecord {
    pub logical_index: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub a: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub b: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub c: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unreadable: Option<String>,
}

impl PostMortem {
    /// Capture in process, under a deadline, from a kernel that is already
    /// frozen (or about to be). Never fails: a section that cannot be taken
    /// is recorded in [`Self::truncated`].
    pub fn capture(
        kernel: Option<&Arc<Kernel>>,
        reason: AbortReason,
        run_id: Option<String>,
    ) -> Self {
        let deadline = Instant::now() + CAPTURE_DEADLINE;
        let mut truncated = Vec::new();
        let mut findings = Vec::new();
        let kernel_snapshot = match kernel {
            None => {
                truncated.push(Truncated {
                    section: "kernel".to_owned(),
                    reason: "no kernel was bound to this runner when the abort fired".to_owned(),
                });
                None
            }
            Some(kernel) => match kernel.forensic_snapshot(deadline) {
                Ok(forensic) => {
                    findings.extend(forensic.findings.iter().map(ToString::to_string));
                    let aux = kernel.debug_aux_provider();
                    let selected = KernelDebugTable::ALL.into_iter().collect();
                    Some(KernelDebugSnapshot::project_with_aux(
                        &forensic.snapshot,
                        &selected,
                        aux.as_deref(),
                    ))
                }
                Err(error) => {
                    truncated.push(Truncated {
                        section: "kernel".to_owned(),
                        reason: error.to_string(),
                    });
                    None
                }
            },
        };

        let event_ring = crate::event_ring::drain_recent(EVENT_RING_RECORDS)
            .into_iter()
            .map(|record| match record {
                Ok(record) => EventRingRecord {
                    logical_index: record.logical_index,
                    kind: Some(record.kind),
                    a: Some(record.a),
                    b: Some(record.b),
                    c: Some(record.c),
                    unreadable: None,
                },
                Err(error) => EventRingRecord {
                    logical_index: error_index(&error),
                    kind: None,
                    a: None,
                    b: None,
                    c: None,
                    unreadable: Some(error.to_string()),
                },
            })
            .collect();

        Self {
            schema: POST_MORTEM_SCHEMA.to_owned(),
            run_id,
            captured_at_unix_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|since| u64::try_from(since.as_millis()).unwrap_or(u64::MAX))
                .unwrap_or(0),
            reason,
            kernel: kernel_snapshot,
            findings,
            event_ring,
            truncated,
        }
    }

    /// Fill a `ProcessGraphLiveness` reason's population fields from THIS
    /// capture's own kernel rows.
    ///
    /// The judge's own census is cheap (`task_count`, `queued_len`) and
    /// deliberately carries no identities: enumerating zombies costs a
    /// snapshot, and taking one before the freeze would name a different
    /// graph from the one in the capture. Deriving them here means the zombie
    /// the error names is literally a row the reader can look up below it.
    pub fn enrich_from_capture(&mut self) {
        let AbortReason::ProcessGraphLiveness {
            live_threads,
            zombies,
            ..
        } = &mut self.reason
        else {
            return;
        };
        let Some(kernel) = &self.kernel else { return };
        if let Some(threads) = &kernel.threads {
            *live_threads = threads.len();
        }
        if let Some(rows) = &kernel.zombies {
            *zombies = rows
                .iter()
                .map(|row| ZombieSummary {
                    id: row.key.id,
                    serial: row.key.serial,
                    parent: row.parent.map(|parent| parent.id),
                })
                .collect();
        }
    }

    /// Where a run writes captures, when it was told to.
    ///
    /// An installed directory wins over the environment, so an embedding
    /// caller that asked for one gets it even under an operator's global
    /// `CARRICK_POSTMORTEM_DIR`.
    pub fn configured_dir() -> Option<PathBuf> {
        if let Some(installed) = INSTALLED_DIR
            .get()
            .and_then(|slot| slot.lock().as_ref().cloned())
        {
            return Some(installed);
        }
        std::env::var_os(POST_MORTEM_DIR_ENV)
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
    }

    /// Install the capture directory for this HOST PROCESS.
    ///
    /// Deliberately not per-container: a post-mortem describes the KERNEL, and
    /// a host process owns exactly one carrier and one kernel graph, so a
    /// per-container scope would be a scope the artifact does not have. The
    /// last caller wins, and that is stated rather than hidden.
    pub fn install_dir(dir: PathBuf) {
        *INSTALLED_DIR
            .get_or_init(|| parking_lot::Mutex::new(None))
            .lock() = Some(dir);
    }

    /// Write `post-mortem.json` and `event-ring.jsonl` under `dir`, creating
    /// it if needed. Returns the JSON path.
    pub fn write_to_dir(&self, dir: &Path) -> std::io::Result<PathBuf> {
        std::fs::create_dir_all(dir)?;
        let json_path = dir.join("post-mortem.json");
        let json = serde_json::to_string_pretty(self)
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        std::fs::write(&json_path, json)?;

        let mut ring = String::new();
        for record in &self.event_ring {
            let line = serde_json::to_string(record)
                .map_err(|error| std::io::Error::other(error.to_string()))?;
            ring.push_str(&line);
            ring.push('\n');
        }
        std::fs::write(dir.join("event-ring.jsonl"), ring)?;
        Ok(json_path)
    }

    /// Write to [`Self::configured_dir`] when one is configured. A write
    /// failure is reported, never silent, and never replaces the abort.
    pub fn persist_if_configured(&self) -> Option<PathBuf> {
        let dir = Self::configured_dir()?;
        match self.write_to_dir(&dir) {
            Ok(path) => {
                tracing::error!(
                    target: "carrick::kernel::post_mortem",
                    path = %path.display(),
                    "kernel aborted; post-mortem written"
                );
                Some(path)
            }
            Err(error) => {
                tracing::error!(
                    target: "carrick::kernel::post_mortem",
                    dir = %dir.display(),
                    %error,
                    "kernel aborted; post-mortem could NOT be written"
                );
                None
            }
        }
    }
}

fn error_index(error: &crate::event_ring::RingReadError) -> u64 {
    use crate::event_ring::RingReadError as E;
    match error {
        E::Busy { logical_index, .. }
        | E::Gap { logical_index, .. }
        | E::Overwritten { logical_index, .. }
        | E::Torn { logical_index, .. }
        | E::UnknownKind { logical_index, .. } => *logical_index,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn liveness_reason(zombies: Vec<ZombieSummary>) -> AbortReason {
        AbortReason::ProcessGraphLiveness {
            unpublished_jobs: 1,
            live_tasks: 0,
            live_threads: 0,
            runnable_rows: 0,
            zombies,
            confirmed_after_ms: 1_500,
        }
    }

    /// The wedge's own signature must be legible without a decoder ring.
    #[test]
    fn the_pid_one_zombie_names_itself_in_the_summary() {
        let reason = liveness_reason(vec![ZombieSummary {
            id: 1,
            serial: 6,
            parent: None,
        }]);
        let summary = reason.summary();
        assert!(
            summary.contains("1 container job(s) unpublished"),
            "{summary}"
        );
        assert!(summary.contains("zombie pid 1 (init)"), "{summary}");
        assert!(summary.contains("no reaper left"), "{summary}");
    }

    #[test]
    fn a_capture_without_a_kernel_records_a_truncation_instead_of_failing() {
        let post_mortem = PostMortem::capture(None, liveness_reason(Vec::new()), None);
        assert!(post_mortem.kernel.is_none());
        assert_eq!(post_mortem.truncated.len(), 1);
        assert_eq!(post_mortem.truncated[0].section, "kernel");
        assert_eq!(post_mortem.schema, POST_MORTEM_SCHEMA);
    }

    #[test]
    fn a_capture_round_trips_through_the_written_directory() {
        crate::event_ring::rec(crate::event_ring::FORK, 11, 22, 33);
        let post_mortem = PostMortem::capture(
            None,
            liveness_reason(vec![ZombieSummary {
                id: 1,
                serial: 6,
                parent: None,
            }]),
            Some("post-mortem-test".to_owned()),
        );
        let dir = tempfile::tempdir().expect("temp dir");
        let path = post_mortem.write_to_dir(dir.path()).expect("write");
        let text = std::fs::read_to_string(&path).expect("read back");
        let decoded: PostMortem = serde_json::from_str(&text).expect("decode");
        assert_eq!(decoded.run_id.as_deref(), Some("post-mortem-test"));
        assert!(matches!(
            decoded.reason,
            AbortReason::ProcessGraphLiveness { .. }
        ));
        let ring = std::fs::read_to_string(dir.path().join("event-ring.jsonl")).expect("ring");
        assert_eq!(
            ring.lines().count(),
            decoded.event_ring.len(),
            "every ring record is one line"
        );
        assert!(
            !decoded.event_ring.is_empty(),
            "the always-on ring must reach the capture with nothing pre-armed"
        );
    }
}
