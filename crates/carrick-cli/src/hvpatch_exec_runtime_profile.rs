//! Strict reader for the six-stage HVPatch exec runtime DTrace protocol.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};

use crate::trace_profile::ProfileCaptureStatus;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct HvpatchExecRuntimeSummary {
    pub(crate) completed_execs: u64,
    pub(crate) stage_events: u64,
}

impl HvpatchExecRuntimeSummary {
    pub(crate) fn from_path(path: &Path, status: ProfileCaptureStatus) -> Result<Self> {
        let contents = fs::read_to_string(path)
            .with_context(|| format!("read HVPatch exec runtime stream {}", path.display()))?;
        Self::from_lines(contents.lines(), status)
    }

    pub(crate) fn from_lines<I, S>(lines: I, status: ProfileCaptureStatus) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        require_lossless(status)?;

        let mut header_seen = false;
        let mut summary = None;
        let mut execs = BTreeMap::<HostExec, ExecState>::new();
        let mut begins = 0_u64;
        let mut completes = 0_u64;
        let mut events = 0_u64;
        let mut phases = [0_u64; 6];

        for raw in lines {
            let line = raw.as_ref();
            if line.is_empty() {
                continue;
            }
            let record = Record::parse(line)?;
            match record.tag.as_str() {
                "header" => {
                    record.exact_fields(&["version"])?;
                    if header_seen || record.u64("version")? != 1 {
                        bail!("duplicate or unsupported HVPATCH4RUNTIME header");
                    }
                    header_seen = true;
                }
                "begin" => {
                    require_header(header_seen)?;
                    record.exact_fields(&[
                        "host_pid",
                        "host_tid",
                        "exec_sequence",
                        "guest_pid",
                        "guest_tid",
                        "asid",
                    ])?;
                    let (key, guest) = record.identities()?;
                    let state = execs.entry(key).or_default();
                    if state.began {
                        bail!("duplicate exec begin for {key:?}");
                    }
                    state.join_guest(guest)?;
                    state.began = true;
                    begins += 1;
                }
                "stage" => {
                    require_header(header_seen)?;
                    record.exact_fields(&[
                        "host_pid",
                        "host_tid",
                        "exec_sequence",
                        "guest_pid",
                        "guest_tid",
                        "asid",
                        "phase",
                        "elapsed_ns",
                        "regions",
                        "mapped_bytes",
                    ])?;
                    let (key, guest) = record.identities()?;
                    let phase = usize::try_from(record.u64("phase")?)
                        .context("HVPATCH4RUNTIME phase exceeds usize")?;
                    if phase >= phases.len() {
                        bail!(
                            "HVPATCH4RUNTIME phase {phase} is outside append-only ordinals 0..=5"
                        );
                    }
                    let state = execs.entry(key).or_default();
                    state.join_guest(guest)?;
                    let bit = 1_u8 << phase;
                    if state.mask & bit != 0 {
                        bail!("duplicate phase {phase} for one completed exec");
                    }
                    state.mask |= bit;
                    state.events += 1;
                    events += 1;
                    phases[phase] += 1;
                    let _ = (
                        record.u64("elapsed_ns")?,
                        record.u64("regions")?,
                        record.u64("mapped_bytes")?,
                    );
                }
                "complete" => {
                    require_header(header_seen)?;
                    record.exact_fields(&[
                        "host_pid",
                        "host_tid",
                        "exec_sequence",
                        "guest_pid",
                        "guest_tid",
                        "asid",
                    ])?;
                    let (key, guest) = record.identities()?;
                    let state = execs.entry(key).or_default();
                    if state.completed {
                        bail!("duplicate exec completion for {key:?}");
                    }
                    state.join_guest(guest)?;
                    state.completed = true;
                    completes += 1;
                }
                "summary" => {
                    require_header(header_seen)?;
                    if summary.is_some() {
                        bail!("duplicate HVPATCH4RUNTIME summary");
                    }
                    summary = Some(Summary::parse(&record)?);
                }
                other => bail!("unknown HVPATCH4RUNTIME record tag {other:?}"),
            }
        }

        if !header_seen {
            bail!("HVPATCH4RUNTIME stream has no header");
        }
        for (key, state) in &execs {
            if !state.began || !state.completed || state.events != 6 || state.mask != 0b11_1111 {
                bail!(
                    "exec {key:?} is unbalanced or incomplete: began={}, completed={}, events={}, ordinal_mask={:#08b}",
                    state.began,
                    state.completed,
                    state.events,
                    state.mask,
                );
            }
        }
        let summary = summary.ok_or_else(|| anyhow!("HVPATCH4RUNTIME stream has no summary"))?;
        summary.validate(begins, completes, events, phases)?;

        Ok(Self {
            completed_execs: completes,
            stage_events: events,
        })
    }

    pub(crate) fn render_human(self) -> String {
        format!(
            "HVPatch exec runtime stages: completed_execs={}, events={}, events_per_exec=6",
            self.completed_execs, self.stage_events
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct HostThread {
    pid: i64,
    tid: i64,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct HostExec {
    host: HostThread,
    sequence: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct GuestExec {
    pid: i64,
    tid: i64,
    asid: u64,
}

#[derive(Clone, Copy, Debug, Default)]
struct ExecState {
    guest: Option<GuestExec>,
    began: bool,
    completed: bool,
    mask: u8,
    events: u64,
}

impl ExecState {
    fn join_guest(&mut self, guest: GuestExec) -> Result<()> {
        if self.guest.is_some_and(|expected| expected != guest) {
            bail!("guest identity disagrees across records for one exec sequence");
        }
        self.guest = Some(guest);
        Ok(())
    }
}

#[derive(Debug)]
struct Record {
    tag: String,
    fields: BTreeMap<String, String>,
}

impl Record {
    fn parse(line: &str) -> Result<Self> {
        let mut parts = line.split('|');
        if parts.next() != Some("HVPATCH4RUNTIME") {
            bail!("unknown HVPATCH4RUNTIME protocol prefix in {line:?}");
        }
        let tag = parts
            .next()
            .filter(|tag| !tag.is_empty())
            .ok_or_else(|| anyhow!("truncated HVPATCH4RUNTIME record"))?
            .to_owned();
        let mut fields = BTreeMap::new();
        for raw in parts {
            let (key, value) = raw
                .split_once('=')
                .ok_or_else(|| anyhow!("HVPATCH4RUNTIME field lacks '=': {raw:?}"))?;
            if key.is_empty()
                || value.is_empty()
                || fields.insert(key.to_owned(), value.to_owned()).is_some()
            {
                bail!("empty or duplicate HVPATCH4RUNTIME field {key:?}");
            }
        }
        Ok(Self { tag, fields })
    }

    fn exact_fields(&self, expected: &[&str]) -> Result<()> {
        let actual = self
            .fields
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let expected = expected.iter().copied().collect::<BTreeSet<_>>();
        if actual != expected {
            bail!("HVPATCH4RUNTIME {:?} field contract mismatch", self.tag);
        }
        Ok(())
    }

    fn value(&self, name: &str) -> Result<&str> {
        self.fields
            .get(name)
            .map(String::as_str)
            .ok_or_else(|| anyhow!("HVPATCH4RUNTIME {:?} lacks {name:?}", self.tag))
    }

    fn u64(&self, name: &str) -> Result<u64> {
        let value = self.value(name)?;
        if value != "0"
            && (!value.bytes().all(|byte| byte.is_ascii_digit()) || value.starts_with('0'))
        {
            bail!("non-canonical unsigned HVPATCH4RUNTIME field {name}={value:?}");
        }
        value.parse().with_context(|| format!("invalid {name}"))
    }

    fn i64(&self, name: &str) -> Result<i64> {
        self.value(name)?
            .parse()
            .with_context(|| format!("invalid {name}"))
    }

    fn identities(&self) -> Result<(HostExec, GuestExec)> {
        let host = HostThread {
            pid: self.i64("host_pid")?,
            tid: self.i64("host_tid")?,
        };
        let guest = GuestExec {
            pid: self.i64("guest_pid")?,
            tid: self.i64("guest_tid")?,
            asid: self.u64("asid")?,
        };
        if host.pid <= 0 || host.tid <= 0 || guest.pid <= 0 || guest.tid <= 0 || guest.asid == 0 {
            bail!("HVPATCH4RUNTIME identities must be positive");
        }
        let sequence = self.u64("exec_sequence")?;
        if sequence == 0 {
            bail!("HVPATCH4RUNTIME exec sequence must be positive");
        }
        Ok((HostExec { host, sequence }, guest))
    }
}

#[derive(Clone, Copy, Debug)]
struct Summary {
    begins: u64,
    completes: u64,
    events: u64,
    phases: [u64; 6],
    join_errors: u64,
    phase_errors: u64,
    duplicate_errors: u64,
    completion_errors: u64,
    lifecycle_errors: u64,
    empty: u64,
    bounded: u64,
    errors: u64,
    drops: u64,
    target_exited: u64,
    target_exit_seen: u64,
    target_exit_code: i64,
}

impl Summary {
    fn parse(record: &Record) -> Result<Self> {
        record.exact_fields(&[
            "status",
            "begins",
            "completes",
            "events",
            "phase0",
            "phase1",
            "phase2",
            "phase3",
            "phase4",
            "phase5",
            "join_errors",
            "phase_errors",
            "duplicate_errors",
            "completion_errors",
            "lifecycle_errors",
            "empty",
            "bounded",
            "errors",
            "drops",
            "target_exited",
            "target_exit_seen",
            "target_exit_code",
            "target_exit_reason",
        ])?;
        if record.value("status")? != "ok" {
            bail!("HVPATCH4RUNTIME producer reported an error");
        }
        let _ = record.u64("target_exit_reason")?;
        Ok(Self {
            begins: record.u64("begins")?,
            completes: record.u64("completes")?,
            events: record.u64("events")?,
            phases: [
                record.u64("phase0")?,
                record.u64("phase1")?,
                record.u64("phase2")?,
                record.u64("phase3")?,
                record.u64("phase4")?,
                record.u64("phase5")?,
            ],
            join_errors: record.u64("join_errors")?,
            phase_errors: record.u64("phase_errors")?,
            duplicate_errors: record.u64("duplicate_errors")?,
            completion_errors: record.u64("completion_errors")?,
            lifecycle_errors: record.u64("lifecycle_errors")?,
            empty: record.u64("empty")?,
            bounded: record.u64("bounded")?,
            errors: record.u64("errors")?,
            drops: record.u64("drops")?,
            target_exited: record.u64("target_exited")?,
            target_exit_seen: record.u64("target_exit_seen")?,
            target_exit_code: record.i64("target_exit_code")?,
        })
    }

    fn validate(self, begins: u64, completes: u64, events: u64, phases: [u64; 6]) -> Result<()> {
        if completes == 0
            || events == 0
            || begins != completes
            || completes.checked_mul(6) != Some(events)
        {
            bail!("HVPATCH4RUNTIME capture is empty, incomplete, or unbalanced");
        }
        if phases != [completes; 6] {
            bail!("HVPATCH4RUNTIME capture does not contain every ordinal exactly once per exec");
        }
        if (self.begins, self.completes, self.events, self.phases)
            != (begins, completes, events, phases)
        {
            bail!("HVPATCH4RUNTIME producer/consumer counts disagree");
        }
        if self.join_errors != 0
            || self.phase_errors != 0
            || self.duplicate_errors != 0
            || self.completion_errors != 0
            || self.lifecycle_errors != 0
            || self.empty != 0
            || self.bounded != 0
            || self.errors != 0
            || self.drops != 0
            || self.target_exited != 1
            || self.target_exit_seen != 1
            || self.target_exit_code != 0
        {
            bail!("HVPATCH4RUNTIME producer summary is not a clean completed capture");
        }
        Ok(())
    }
}

fn require_header(seen: bool) -> Result<()> {
    if !seen {
        bail!("HVPATCH4RUNTIME data precedes its header");
    }
    Ok(())
}

fn require_lossless(status: ProfileCaptureStatus) -> Result<()> {
    if status != ProfileCaptureStatus::default() {
        bail!(
            "HVPATCH4RUNTIME capture is not lossless: principal={}, aggregation={}, dynamic={}, dynamic_rinse={}, dynamic_dirty={}, other={}, interrupted={}",
            status.principal_drops,
            status.aggregation_drops,
            status.dynamic_drops,
            status.dynamic_rinse_drops,
            status.dynamic_dirty_drops,
            status.other_drops,
            status.interrupted,
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEADER: &str = "HVPATCH4RUNTIME|header|version=1";
    const BEGIN: &str = "HVPATCH4RUNTIME|begin|host_pid=10|host_tid=20|exec_sequence=1|guest_pid=30|guest_tid=40|asid=50";
    const COMPLETE: &str = "HVPATCH4RUNTIME|complete|host_pid=10|host_tid=20|exec_sequence=1|guest_pid=30|guest_tid=40|asid=50";

    fn stage(phase: u32) -> String {
        format!(
            "HVPATCH4RUNTIME|stage|host_pid=10|host_tid=20|exec_sequence=1|guest_pid=30|guest_tid=40|asid=50|phase={phase}|elapsed_ns=1|regions=2|mapped_bytes=3"
        )
    }

    fn summary(overrides: &[(&str, &str)]) -> String {
        let mut values = std::collections::BTreeMap::from([
            ("status", "ok"),
            ("begins", "1"),
            ("completes", "1"),
            ("events", "6"),
            ("phase0", "1"),
            ("phase1", "1"),
            ("phase2", "1"),
            ("phase3", "1"),
            ("phase4", "1"),
            ("phase5", "1"),
            ("join_errors", "0"),
            ("phase_errors", "0"),
            ("duplicate_errors", "0"),
            ("completion_errors", "0"),
            ("lifecycle_errors", "0"),
            ("empty", "0"),
            ("bounded", "0"),
            ("errors", "0"),
            ("drops", "0"),
            ("target_exited", "1"),
            ("target_exit_seen", "1"),
            ("target_exit_code", "0"),
            ("target_exit_reason", "1"),
        ]);
        for &(key, value) in overrides {
            values.insert(key, value);
        }
        let mut line = "HVPATCH4RUNTIME|summary".to_owned();
        for (key, value) in values {
            line.push('|');
            line.push_str(key);
            line.push('=');
            line.push_str(value);
        }
        line
    }

    fn valid_lines() -> Vec<String> {
        let mut lines = vec![HEADER.to_owned(), BEGIN.to_owned()];
        lines.extend((0..6).map(stage));
        lines.push(COMPLETE.to_owned());
        lines.push(summary(&[]));
        lines
    }

    #[test]
    fn accepts_exactly_six_unique_stages_for_each_completed_exec() {
        let accepted =
            HvpatchExecRuntimeSummary::from_lines(valid_lines(), ProfileCaptureStatus::default())
                .expect("complete six-stage stream");
        assert_eq!(accepted.completed_execs, 1);
        assert_eq!(accepted.stage_events, 6);
    }

    #[test]
    fn accepts_dtrace_buffer_reordering_within_one_exec_sequence() {
        let mut lines = valid_lines();
        let complete = lines.remove(8);
        lines.insert(3, complete);
        let accepted =
            HvpatchExecRuntimeSummary::from_lines(lines, ProfileCaptureStatus::default())
                .expect("sequence key makes DTrace output ordering irrelevant");
        assert_eq!(accepted.completed_execs, 1);
        assert_eq!(accepted.stage_events, 6);
    }

    #[test]
    fn rejects_empty_missing_duplicate_and_unbalanced_streams() {
        for (name, lines) in [
            (
                "empty",
                vec![
                    HEADER.to_owned(),
                    summary(&[
                        ("status", "error"),
                        ("begins", "0"),
                        ("completes", "0"),
                        ("events", "0"),
                        ("phase0", "0"),
                        ("phase1", "0"),
                        ("phase2", "0"),
                        ("phase3", "0"),
                        ("phase4", "0"),
                        ("phase5", "0"),
                        ("empty", "1"),
                    ]),
                ],
            ),
            ("missing", {
                let mut lines = valid_lines();
                lines.remove(3);
                lines
            }),
            ("duplicate", {
                let mut lines = valid_lines();
                lines.insert(3, stage(0));
                lines
            }),
            ("unbalanced", {
                let mut lines = valid_lines();
                lines.remove(8);
                lines
            }),
        ] {
            assert!(
                HvpatchExecRuntimeSummary::from_lines(lines, ProfileCaptureStatus::default())
                    .is_err(),
                "{name} stream was accepted"
            );
        }
    }

    #[test]
    fn rejects_timeout_provider_error_drops_and_interruption() {
        for (name, status, overrides) in [
            (
                "timeout",
                ProfileCaptureStatus::default(),
                vec![("status", "error"), ("bounded", "1")],
            ),
            (
                "provider-error",
                ProfileCaptureStatus::default(),
                vec![("status", "error"), ("errors", "1")],
            ),
            (
                "drop",
                ProfileCaptureStatus {
                    principal_drops: 1,
                    ..ProfileCaptureStatus::default()
                },
                vec![],
            ),
            (
                "producer-drop",
                ProfileCaptureStatus::default(),
                vec![("status", "error"), ("drops", "1")],
            ),
            (
                "interruption",
                ProfileCaptureStatus {
                    interrupted: true,
                    ..ProfileCaptureStatus::default()
                },
                vec![],
            ),
        ] {
            let mut lines = valid_lines();
            *lines.last_mut().expect("summary") = summary(&overrides);
            assert!(
                HvpatchExecRuntimeSummary::from_lines(lines, status).is_err(),
                "{name} stream was accepted"
            );
        }
    }
}
