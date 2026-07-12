use std::collections::{BTreeMap, btree_map::Entry};
use std::fs;
use std::io::Write;
use std::os::fd::AsRawFd;
use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};
use serde::Serialize;
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;

use crate::perf_stats::{Summary, summarize};

const PROTOCOL_PREFIX: &str = "DSRPROF1";
const JSON_SCHEMA: &str = "carrick.dsr-profile.v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RecordType {
    Count,
    Total,
    Minimum,
    Maximum,
    Sample,
    Incomplete,
    HighWater,
    Complete,
}

impl RecordType {
    fn parse(value: &str) -> Result<Self> {
        match value {
            "count" => Ok(Self::Count),
            "total" => Ok(Self::Total),
            "minimum" => Ok(Self::Minimum),
            "maximum" => Ok(Self::Maximum),
            "sample" => Ok(Self::Sample),
            "incomplete" => Ok(Self::Incomplete),
            "high-water" => Ok(Self::HighWater),
            "complete" => Ok(Self::Complete),
            other => bail!("unknown {PROTOCOL_PREFIX} record type {other:?}"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, clap::ValueEnum, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum TraceProfileKind {
    Dsr,
    DsrIndirect,
    DsrFork,
}

impl TraceProfileKind {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Dsr => "dsr",
            Self::DsrIndirect => "dsr-indirect",
            Self::DsrFork => "dsr-fork",
        }
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn bundled_script(self) -> &'static str {
        match self {
            Self::Dsr => carrick_runtime::dtrace_consumer::BUNDLED_DSR_PROFILE_D,
            Self::DsrIndirect => carrick_runtime::dtrace_consumer::BUNDLED_DSR_INDIRECT_D,
            Self::DsrFork => carrick_runtime::dtrace_consumer::BUNDLED_DSR_FORK_D,
        }
    }

    fn parse_protocol(value: &str) -> Result<Self> {
        match value {
            "dsr" => Ok(Self::Dsr),
            "dsr-indirect" => Ok(Self::DsrIndirect),
            "dsr-fork" => Ok(Self::DsrFork),
            other => bail!("unknown DSR profile {other:?}"),
        }
    }
}

#[derive(Debug)]
struct ProfileRecord {
    record_type: RecordType,
    fields: BTreeMap<String, String>,
}

impl ProfileRecord {
    fn parse(line: &str) -> Result<Self> {
        let mut parts = line.split('|');
        let prefix = parts
            .next()
            .ok_or_else(|| anyhow!("empty profile record"))?;
        if prefix != PROTOCOL_PREFIX {
            bail!("unknown profile protocol prefix {prefix:?}");
        }
        let record_type = RecordType::parse(
            parts
                .next()
                .ok_or_else(|| anyhow!("truncated {PROTOCOL_PREFIX} record"))?,
        )?;
        let mut fields = BTreeMap::new();
        for raw_field in parts {
            let (key, value) = raw_field
                .split_once('=')
                .ok_or_else(|| anyhow!("profile field lacks '=': {raw_field:?}"))?;
            if key.is_empty() {
                bail!("profile field has an empty key");
            }
            if value.is_empty() {
                bail!("profile field {key:?} has an empty value");
            }
            match fields.entry(key.to_owned()) {
                Entry::Vacant(slot) => {
                    slot.insert(value.to_owned());
                }
                Entry::Occupied(_) => bail!("duplicate profile field {key:?}"),
            }
        }

        let record = Self {
            record_type,
            fields,
        };
        record.validate_integer_fields()?;
        Ok(record)
    }

    fn validate_integer_fields(&self) -> Result<()> {
        for key in [
            "pid",
            "tid",
            "source_pc",
            "target_pc",
            "duration_ns",
            "interval",
            "value",
            "value_ns",
            "used",
            "capacity",
            "bounded",
        ] {
            if let Some(value) = self.fields.get(key) {
                parse_u64(value).with_context(|| format!("invalid integer field {key:?}"))?;
            }
        }
        Ok(())
    }

    fn required(&self, key: &str) -> Result<&str> {
        self.fields
            .get(key)
            .map(String::as_str)
            .ok_or_else(|| anyhow!("profile record is missing required field {key:?}"))
    }

    fn required_u64(&self, key: &str) -> Result<u64> {
        parse_u64(self.required(key)?)
            .with_context(|| format!("invalid required integer field {key:?}"))
    }

    fn optional_u64(&self, key: &str) -> Result<Option<u64>> {
        self.fields
            .get(key)
            .map(|value| parse_u64(value))
            .transpose()
            .with_context(|| format!("invalid optional integer field {key:?}"))
    }
}

fn parse_u64(value: &str) -> Result<u64> {
    if let Some(hex) = value.strip_prefix("0x") {
        u64::from_str_radix(hex, 16)
            .with_context(|| format!("invalid hexadecimal integer {value:?}"))
    } else {
        value
            .parse::<u64>()
            .with_context(|| format!("invalid decimal integer {value:?}"))
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub(crate) struct ProfileCaptureStatus {
    pub(crate) principal_drops: u64,
    pub(crate) aggregation_drops: u64,
    pub(crate) dynamic_drops: u64,
    pub(crate) other_drops: u64,
}

#[cfg(target_os = "macos")]
impl From<carrick_runtime::dtrace_consumer::DTraceRunReport> for ProfileCaptureStatus {
    fn from(report: carrick_runtime::dtrace_consumer::DTraceRunReport) -> Self {
        Self {
            principal_drops: report.principal_drops,
            aggregation_drops: report.aggregation_drops,
            dynamic_drops: report.dynamic_drops,
            other_drops: report.other_drops,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct ProfileProvenance {
    pub(crate) run_id: String,
    pub(crate) git_sha: String,
    pub(crate) git_dirty: Option<bool>,
    pub(crate) binary_sha256: String,
    pub(crate) command: Vec<String>,
    pub(crate) host: String,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub(crate) struct ProfileScope {
    #[serde(skip_serializing_if = "Option::is_none")]
    phase: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pid: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tid: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_pc: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    target_pc: Option<u64>,
}

impl ProfileScope {
    fn from_record(record: &ProfileRecord) -> Result<Self> {
        Ok(Self {
            phase: record.fields.get("phase").cloned(),
            pid: record.optional_u64("pid")?,
            tid: record.optional_u64("tid")?,
            kind: record.fields.get("kind").cloned(),
            source_pc: record.optional_u64("source_pc")?,
            target_pc: record.optional_u64("target_pc")?,
        })
    }
}

#[derive(Default)]
struct MetricBuilder {
    count: Option<u64>,
    total_ns: Option<u64>,
    minimum_ns: Option<u64>,
    maximum_ns: Option<u64>,
    samples_ns: Vec<f64>,
    sampling_interval: Option<u64>,
    incomplete: u64,
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub(crate) enum ProfileMetric {
    Exact {
        #[serde(skip_serializing_if = "Option::is_none")]
        count: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        total_ns: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        minimum_ns: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        maximum_ns: Option<u64>,
    },
    SampledDuration {
        summary: Summary,
    },
    IncompletePair {
        value: u64,
    },
    HighWater {
        metric: String,
        used: u64,
        capacity: u64,
    },
    Completion,
}

#[derive(Clone, Copy, Debug, Serialize)]
pub(crate) struct CompletionState {
    complete: bool,
    bounded: bool,
    high_cardinality_overflow: bool,
    incomplete_pairs: u64,
    drops: ProfileCaptureStatus,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct ProfileJsonRow {
    schema: &'static str,
    profile: TraceProfileKind,
    run_id: String,
    git_sha: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    git_dirty: Option<bool>,
    binary_sha256: String,
    command: Vec<String>,
    host: String,
    scope: ProfileScope,
    metric: ProfileMetric,
    #[serde(skip_serializing_if = "Option::is_none")]
    sampling_interval: Option<u64>,
    completion: CompletionState,
}

#[derive(Clone, Debug)]
struct ProfileOutputMetric {
    scope: ProfileScope,
    metric: ProfileMetric,
    sampling_interval: Option<u64>,
}

#[derive(Debug)]
pub(crate) struct ProfileSummary {
    profile: TraceProfileKind,
    completion: CompletionState,
    metrics: Vec<ProfileOutputMetric>,
    provenance: ProfileProvenance,
}

impl ProfileSummary {
    pub(crate) fn from_path(path: &Path, capture_status: ProfileCaptureStatus) -> Result<Self> {
        let contents = fs::read_to_string(path)
            .with_context(|| format!("read DSR profile stream {}", path.display()))?;
        Self::from_lines(contents.lines(), capture_status)
    }

    pub(crate) fn from_lines<I, S>(lines: I, capture_status: ProfileCaptureStatus) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        if capture_status.principal_drops != 0 {
            bail!(
                "DTrace principal buffer dropped {} record(s); profile stream is truncated",
                capture_status.principal_drops
            );
        }

        let mut grouped = BTreeMap::<ProfileScope, MetricBuilder>::new();
        let mut high_water = BTreeMap::<(ProfileScope, String), (u64, u64)>::new();
        let mut completion = None;

        for (index, raw_line) in lines.into_iter().enumerate() {
            let line = raw_line.as_ref().trim();
            if line.is_empty() {
                continue;
            }
            if completion.is_some() {
                bail!(
                    "profile record appears after completion at line {}",
                    index + 1
                );
            }
            let record = ProfileRecord::parse(line)
                .with_context(|| format!("invalid profile record at line {}", index + 1))?;
            if record.record_type == RecordType::Complete {
                let profile = TraceProfileKind::parse_protocol(record.required("profile")?)?;
                let bounded = match record.required_u64("bounded")? {
                    0 => false,
                    1 => true,
                    other => bail!("completion bounded field must be 0 or 1, got {other}"),
                };
                completion = Some((profile, bounded));
                continue;
            }

            let scope = ProfileScope::from_record(&record)?;
            match record.record_type {
                RecordType::Count => {
                    let value = record.required_u64("value")?;
                    let builder = grouped.entry(scope).or_default();
                    builder.count = Some(builder.count.unwrap_or(0).saturating_add(value));
                }
                RecordType::Total => {
                    let value = record.required_u64("value_ns")?;
                    let builder = grouped.entry(scope).or_default();
                    builder.total_ns = Some(builder.total_ns.unwrap_or(0).saturating_add(value));
                }
                RecordType::Minimum => {
                    let value = record.required_u64("value_ns")?;
                    let builder = grouped.entry(scope).or_default();
                    builder.minimum_ns =
                        Some(builder.minimum_ns.map_or(value, |old| old.min(value)));
                }
                RecordType::Maximum => {
                    let value = record.required_u64("value_ns")?;
                    let builder = grouped.entry(scope).or_default();
                    builder.maximum_ns =
                        Some(builder.maximum_ns.map_or(value, |old| old.max(value)));
                }
                RecordType::Sample => {
                    let duration = record.required_u64("duration_ns")?;
                    let interval = record.optional_u64("interval")?;
                    let builder = grouped.entry(scope).or_default();
                    if let (Some(previous), Some(current)) = (builder.sampling_interval, interval)
                        && previous != current
                    {
                        bail!(
                            "sample group mixes intervals {previous} and {current} at line {}",
                            index + 1
                        );
                    }
                    if interval.is_some() {
                        builder.sampling_interval = interval;
                    }
                    builder.samples_ns.push(duration as f64);
                }
                RecordType::Incomplete => {
                    let value = record.required_u64("value")?;
                    let builder = grouped.entry(scope).or_default();
                    builder.incomplete = builder.incomplete.saturating_add(value);
                }
                RecordType::HighWater => {
                    let metric = record.required("metric")?.to_owned();
                    let used = record.required_u64("used")?;
                    let capacity = record.required_u64("capacity")?;
                    high_water
                        .entry((scope, metric))
                        .and_modify(|current| {
                            current.0 = current.0.max(used);
                            current.1 = current.1.max(capacity);
                        })
                        .or_insert((used, capacity));
                }
                RecordType::Complete => unreachable!("completion handled above"),
            }
        }

        let (profile, bounded) =
            completion.ok_or_else(|| anyhow!("profile stream is missing its completion record"))?;
        let incomplete_pairs = grouped.values().fold(0_u64, |total, builder| {
            total.saturating_add(builder.incomplete)
        });
        let completion = CompletionState {
            complete: !bounded
                && incomplete_pairs == 0
                && capture_status.aggregation_drops == 0
                && capture_status.dynamic_drops == 0
                && capture_status.other_drops == 0,
            bounded,
            high_cardinality_overflow: capture_status.aggregation_drops != 0
                || capture_status.dynamic_drops != 0,
            incomplete_pairs,
            drops: capture_status,
        };

        let mut metrics = Vec::new();
        for (scope, builder) in grouped {
            if builder.count.is_some()
                || builder.total_ns.is_some()
                || builder.minimum_ns.is_some()
                || builder.maximum_ns.is_some()
            {
                metrics.push(ProfileOutputMetric {
                    scope: scope.clone(),
                    metric: ProfileMetric::Exact {
                        count: builder.count,
                        total_ns: builder.total_ns,
                        minimum_ns: builder.minimum_ns,
                        maximum_ns: builder.maximum_ns,
                    },
                    sampling_interval: None,
                });
            }
            if let Some(summary) = summarize(&builder.samples_ns) {
                metrics.push(ProfileOutputMetric {
                    scope: scope.clone(),
                    metric: ProfileMetric::SampledDuration { summary },
                    sampling_interval: builder.sampling_interval,
                });
            }
            if builder.incomplete != 0 {
                metrics.push(ProfileOutputMetric {
                    scope,
                    metric: ProfileMetric::IncompletePair {
                        value: builder.incomplete,
                    },
                    sampling_interval: None,
                });
            }
        }
        for ((scope, metric), (used, capacity)) in high_water {
            metrics.push(ProfileOutputMetric {
                scope,
                metric: ProfileMetric::HighWater {
                    metric,
                    used,
                    capacity,
                },
                sampling_interval: None,
            });
        }
        metrics.push(ProfileOutputMetric {
            scope: ProfileScope {
                phase: None,
                pid: None,
                tid: None,
                kind: None,
                source_pc: None,
                target_pc: None,
            },
            metric: ProfileMetric::Completion,
            sampling_interval: None,
        });

        Ok(Self {
            profile,
            completion,
            metrics,
            provenance: ProfileProvenance::default(),
        })
    }

    pub(crate) fn set_provenance(&mut self, provenance: ProfileProvenance) {
        self.provenance = provenance;
    }

    pub(crate) fn require_profile(&self, expected: TraceProfileKind) -> Result<()> {
        if self.profile != expected {
            bail!(
                "profile stream completed as {}, expected {}",
                self.profile.as_str(),
                expected.as_str()
            );
        }
        Ok(())
    }

    pub(crate) fn render_human(&self) -> String {
        format!(
            "DSR profile {}: {} metric row(s), complete={}, bounded={}, incomplete_pairs={}, drops={}/{}/{}/{}",
            self.profile.as_str(),
            self.metrics.len().saturating_sub(1),
            self.completion.complete,
            self.completion.bounded,
            self.completion.incomplete_pairs,
            self.completion.drops.principal_drops,
            self.completion.drops.aggregation_drops,
            self.completion.drops.dynamic_drops,
            self.completion.drops.other_drops,
        )
    }

    fn json_rows(&self) -> Vec<ProfileJsonRow> {
        self.metrics
            .iter()
            .map(|output| ProfileJsonRow {
                schema: JSON_SCHEMA,
                profile: self.profile,
                run_id: self.provenance.run_id.clone(),
                git_sha: self.provenance.git_sha.clone(),
                git_dirty: self.provenance.git_dirty,
                binary_sha256: self.provenance.binary_sha256.clone(),
                command: self.provenance.command.clone(),
                host: self.provenance.host.clone(),
                scope: output.scope.clone(),
                metric: output.metric.clone(),
                sampling_interval: output.sampling_interval,
                completion: self.completion,
            })
            .collect()
    }
}

pub(crate) fn capture_provenance(binary: &Path, command: &[String]) -> Result<ProfileProvenance> {
    let binary_bytes =
        fs::read(binary).with_context(|| format!("read traced binary {}", binary.display()))?;
    let binary_sha256 = format!("{:x}", Sha256::digest(binary_bytes));
    let git_sha = command_output("git", &["rev-parse", "HEAD"]).unwrap_or_else(|| "unknown".into());
    let git_dirty = git_dirty();
    let host = command_output("hostname", &[]).unwrap_or_else(|| "unknown".into());
    let run_id = std::env::var("CARRICK_RUN_ID").unwrap_or_else(|_| {
        format!(
            "dsr-{}-{}",
            chrono::Utc::now().format("%Y%m%dT%H%M%S%.3fZ"),
            std::process::id()
        )
    });
    Ok(ProfileProvenance {
        run_id,
        git_sha,
        git_dirty,
        binary_sha256,
        command: command.to_vec(),
        host,
    })
}

fn git_dirty() -> Option<bool> {
    let output = std::process::Command::new("git")
        .args(["status", "--porcelain"])
        .output()
        .ok()?;
    output.status.success().then_some(!output.stdout.is_empty())
}

fn command_output(program: &str, args: &[&str]) -> Option<String> {
    let output = std::process::Command::new(program)
        .args(args)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8(output.stdout).ok()?;
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_owned())
}

pub(crate) fn write_summary_atomic(
    path: &Path,
    summary: &ProfileSummary,
    owner: Option<(u32, u32)>,
) -> Result<()> {
    let parent = path
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent)
        .with_context(|| format!("create profile output directory {}", parent.display()))?;
    let mut temporary = NamedTempFile::new_in(parent)
        .with_context(|| format!("create temporary profile in {}", parent.display()))?;
    for row in summary.json_rows() {
        serde_json::to_writer(&mut temporary, &row).context("serialize DSR profile row")?;
        temporary
            .write_all(b"\n")
            .context("terminate DSR profile row")?;
    }
    temporary.flush().context("flush DSR profile JSONL")?;
    temporary
        .as_file()
        .sync_all()
        .context("sync DSR profile JSONL")?;
    if let Some((uid, gid)) = owner {
        let result = unsafe { libc::fchown(temporary.as_raw_fd(), uid, gid) };
        if result != 0 {
            return Err(std::io::Error::last_os_error()).context("set DSR profile owner");
        }
    }
    temporary
        .persist(path)
        .map_err(|error| anyhow!("publish DSR profile {}: {}", path.display(), error.error))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_sample_and_completion() {
        let sample = ProfileRecord::parse(
            "DSRPROF1|sample|phase=run|pid=42|tid=7|kind=3|duration_ns=9000|interval=1024",
        )
        .expect("sample");
        assert_eq!(sample.record_type, RecordType::Sample);
        assert_eq!(sample.required_u64("duration_ns").expect("duration"), 9000);
        ProfileRecord::parse("DSRPROF1|complete|profile=dsr|bounded=0").expect("complete");
    }

    #[test]
    fn rejects_unknown_duplicate_and_truncated_protocol() {
        assert!(ProfileRecord::parse("DSRPROF2|complete").is_err());
        assert!(ProfileRecord::parse("DSRPROF1|count|kind=1|kind=2").is_err());
        assert!(ProfileRecord::parse("DSRPROF1|count|pid=not-a-number").is_err());
        assert!(
            ProfileSummary::from_lines(
                ["DSRPROF1|count|phase=run|pid=1|kind=3|value=9"],
                ProfileCaptureStatus::default(),
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_duplicate_completion_and_records_after_completion() {
        for lines in [
            vec![
                "DSRPROF1|complete|profile=dsr|bounded=0",
                "DSRPROF1|complete|profile=dsr|bounded=0",
            ],
            vec![
                "DSRPROF1|complete|profile=dsr|bounded=0",
                "DSRPROF1|count|phase=run|value=1",
            ],
        ] {
            assert!(ProfileSummary::from_lines(lines, ProfileCaptureStatus::default()).is_err());
        }
    }

    #[test]
    fn aggregates_exact_samples_incomplete_and_high_water() {
        let summary = ProfileSummary::from_lines(
            [
                "DSRPROF1|count|phase=run|pid=10|kind=3|value=9",
                "DSRPROF1|count|phase=run|pid=10|kind=3|value=2",
                "DSRPROF1|total|phase=run|pid=10|kind=3|value_ns=90000",
                "DSRPROF1|minimum|phase=run|pid=10|kind=3|value_ns=7000",
                "DSRPROF1|maximum|phase=run|pid=10|kind=3|value_ns=15000",
                "DSRPROF1|sample|phase=run|pid=10|kind=3|duration_ns=9000|interval=1024",
                "DSRPROF1|incomplete|phase=prepare|pid=10|kind=overwrite|value=1",
                "DSRPROF1|high-water|metric=cache-bytes|pid=10|used=4096|capacity=67108864",
                "DSRPROF1|complete|profile=dsr|bounded=0",
            ],
            ProfileCaptureStatus::default(),
        )
        .expect("profile summary");
        let rows = summary.json_rows();
        assert!(!summary.completion.complete);
        assert_eq!(summary.completion.incomplete_pairs, 1);
        assert_eq!(rows.len(), 5);
        assert!(rows.iter().any(|row| matches!(
            row.metric,
            ProfileMetric::Exact {
                count: Some(11),
                total_ns: Some(90_000),
                minimum_ns: Some(7_000),
                maximum_ns: Some(15_000)
            }
        )));
        assert!(
            rows.iter()
                .any(|row| matches!(row.metric, ProfileMetric::IncompletePair { value: 1 }))
        );
        assert!(rows.iter().any(|row| matches!(
            row.metric,
            ProfileMetric::HighWater {
                used: 4_096,
                capacity: 67_108_864,
                ..
            }
        )));
    }

    #[test]
    fn parses_hex_guest_pcs_and_marks_aggregation_loss_incomplete() {
        let status = ProfileCaptureStatus {
            aggregation_drops: 2,
            ..ProfileCaptureStatus::default()
        };
        let summary = ProfileSummary::from_lines(
            [
                "DSRPROF1|count|phase=indirect-pair|pid=10|source_pc=0x4000|target_pc=0x8000|value=7",
                "DSRPROF1|complete|profile=dsr-indirect|bounded=0",
            ],
            status,
        )
        .expect("profile summary");
        assert!(!summary.completion.complete);
        assert!(summary.completion.high_cardinality_overflow);
        assert_eq!(summary.metrics[0].scope.source_pc, Some(0x4000));
        assert_eq!(summary.metrics[0].scope.target_pc, Some(0x8000));
    }

    #[test]
    fn principal_drops_are_a_truncated_stream_error() {
        let status = ProfileCaptureStatus {
            principal_drops: 1,
            ..ProfileCaptureStatus::default()
        };
        assert!(
            ProfileSummary::from_lines(["DSRPROF1|complete|profile=dsr|bounded=0"], status)
                .is_err()
        );
    }

    #[test]
    fn requested_profile_must_match_stream_completion() {
        let summary = ProfileSummary::from_lines(
            ["DSRPROF1|complete|profile=dsr-fork|bounded=0"],
            ProfileCaptureStatus::default(),
        )
        .expect("summary");
        assert!(summary.require_profile(TraceProfileKind::Dsr).is_err());
        summary
            .require_profile(TraceProfileKind::DsrFork)
            .expect("matching profile");
    }

    #[test]
    fn writes_provenance_rich_jsonl_atomically() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("profile.jsonl");
        let mut summary = ProfileSummary::from_lines(
            ["DSRPROF1|complete|profile=dsr-fork|bounded=0"],
            ProfileCaptureStatus::default(),
        )
        .expect("summary");
        summary.set_provenance(ProfileProvenance {
            run_id: "test-run".to_owned(),
            git_sha: "abc123".to_owned(),
            git_dirty: Some(true),
            binary_sha256: "def456".to_owned(),
            command: vec!["run-elf".to_owned(), "fixture".to_owned()],
            host: "test-host".to_owned(),
        });
        write_summary_atomic(&path, &summary, None).expect("write summary");
        let contents = fs::read_to_string(path).expect("read summary");
        let row: serde_json::Value = serde_json::from_str(contents.trim()).expect("JSON row");
        assert_eq!(row["schema"], JSON_SCHEMA);
        assert_eq!(row["run_id"], "test-run");
        assert_eq!(row["git_dirty"], true);
        assert_eq!(row["metric"]["type"], "completion");
    }
}
