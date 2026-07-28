use std::collections::{BTreeMap, btree_map::Entry};
use std::fs;
use std::io::{BufWriter, Write};
use std::os::fd::AsRawFd;
use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;

use crate::perf_stats::{Summary, summarize};
#[cfg(target_os = "macos")]
use carrick_runtime::dtrace_symbols::{
    KERNEL_SYMBOL_SCHEMA, KernelIdentity, KernelObjectRange, KernelSymbolRange,
    KernelSymbolSnapshot,
};

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
    NativeWall,
}

impl TraceProfileKind {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Dsr => "dsr",
            Self::DsrIndirect => "dsr-indirect",
            Self::DsrFork => "dsr-fork",
            Self::NativeWall => "native-wall",
        }
    }

    pub(crate) const fn requires_runtime_profile(self) -> bool {
        matches!(self, Self::Dsr | Self::DsrFork)
    }

    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    pub(crate) fn bundled_script(self) -> &'static str {
        match self {
            Self::Dsr => carrick_runtime::dtrace_consumer::BUNDLED_DSR_PROFILE_D,
            Self::DsrIndirect => carrick_runtime::dtrace_consumer::BUNDLED_DSR_INDIRECT_D,
            Self::DsrFork => carrick_runtime::dtrace_consumer::BUNDLED_DSR_FORK_D,
            Self::NativeWall => carrick_runtime::dtrace_consumer::BUNDLED_NATIVE_WALL_D,
        }
    }

    fn parse_protocol(value: &str) -> Result<Self> {
        match value {
            "dsr" => Ok(Self::Dsr),
            "dsr-indirect" => Ok(Self::DsrIndirect),
            "dsr-fork" => Ok(Self::DsrFork),
            "native-wall" => Ok(Self::NativeWall),
            other => bail!("unknown DSR profile {other:?}"),
        }
    }
}

#[derive(Debug)]
struct ProfileRecord {
    record_type: RecordType,
    fields: BTreeMap<String, String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StackTraceValue {
    Count(u64),
    DurationNs(u64),
}

#[derive(Debug)]
struct StackTraceRecord {
    state: String,
    pid: Option<u64>,
    value: StackTraceValue,
    frames: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct HostImageRangeRecord {
    start: u64,
    end: u64,
    path: String,
}

#[derive(Debug, Deserialize)]
struct HostImageCatalogRecord {
    pid: u64,
    ranges: Vec<HostImageRangeRecord>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum HostImageCatalogEnvelope {
    Ok { ok: HostImageCatalogRecord },
    Err { err: String },
}

impl HostImageCatalogRecord {
    fn parse(line: &str) -> Result<Self> {
        let payload = line
            .strip_prefix("NWIMAGES1|")
            .ok_or_else(|| anyhow!("invalid native-wall image catalog prefix"))?;
        let envelope: HostImageCatalogEnvelope =
            serde_json::from_str(payload).context("invalid image catalog JSON")?;
        let catalog = match envelope {
            HostImageCatalogEnvelope::Ok { ok } => ok,
            HostImageCatalogEnvelope::Err { err } => {
                bail!("image catalog probe serialization failed: {err}")
            }
        };
        if catalog.ranges.is_empty() {
            bail!("image catalog for pid {} has no ranges", catalog.pid);
        }
        for range in &catalog.ranges {
            if range.start >= range.end {
                bail!(
                    "image catalog for pid {} has invalid range {:#x}..{:#x}",
                    catalog.pid,
                    range.start,
                    range.end
                );
            }
        }
        Ok(catalog)
    }
}

impl StackTraceRecord {
    fn begin(line: &str) -> Result<Self> {
        let mut parts = line.split('|');
        if parts.next() != Some("NWSTACK1") || parts.next() != Some("begin") {
            bail!("invalid native-wall stack header");
        }
        let mut fields = BTreeMap::new();
        for raw_field in parts {
            let (key, value) = raw_field
                .split_once('=')
                .ok_or_else(|| anyhow!("stack field lacks '=': {raw_field:?}"))?;
            if key.is_empty() || value.is_empty() {
                bail!("stack field has an empty key or value");
            }
            match fields.entry(key.to_owned()) {
                Entry::Vacant(slot) => {
                    slot.insert(value.to_owned());
                }
                Entry::Occupied(_) => bail!("duplicate stack field {key:?}"),
            }
        }
        let required = |key: &str| {
            fields
                .get(key)
                .map(String::as_str)
                .ok_or_else(|| anyhow!("stack record is missing {key:?}"))
        };
        let state = required("state")?.to_owned();
        let (pid, value) = match state.as_str() {
            "kernel-oncpu"
                if fields
                    .keys()
                    .map(String::as_str)
                    .eq(["state", "value"].into_iter()) =>
            {
                (
                    None,
                    StackTraceValue::Count(
                        parse_u64(required("value")?).context("invalid stack count")?,
                    ),
                )
            }
            "voluntary"
                if fields
                    .keys()
                    .map(String::as_str)
                    .eq(["pid", "state", "value_ns"].into_iter()) =>
            {
                (
                    Some(parse_u64(required("pid")?).context("invalid stack pid")?),
                    StackTraceValue::DurationNs(
                        parse_u64(required("value_ns")?).context("invalid stack duration")?,
                    ),
                )
            }
            _ => bail!("stack record has an invalid state/field/value contract"),
        };
        if pid == Some(0) {
            bail!("stack pid must be positive");
        }
        match value {
            StackTraceValue::Count(0) => bail!("stack count must be positive"),
            StackTraceValue::DurationNs(0) => bail!("stack duration must be positive"),
            StackTraceValue::Count(_) | StackTraceValue::DurationNs(_) => {}
        }
        Ok(Self {
            state,
            pid,
            value,
            frames: Vec::new(),
        })
    }
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

#[cfg(target_os = "macos")]
fn raw_kernel_address(frame: &str) -> Result<u64> {
    let digits = frame
        .strip_prefix("0x")
        .filter(|digits| !digits.is_empty())
        .ok_or_else(|| anyhow!("kernel stack frame {frame:?} is not raw hexadecimal"))?;
    if !digits.bytes().all(|value| value.is_ascii_hexdigit()) {
        bail!("kernel stack frame {frame:?} is not raw hexadecimal");
    }
    u64::from_str_radix(digits, 16)
        .with_context(|| format!("kernel stack frame {frame:?} is outside u64"))
}

#[cfg(target_os = "macos")]
pub(crate) fn kernel_stack_addresses_from_path(path: &Path) -> Result<Vec<u64>> {
    let contents = fs::read_to_string(path)
        .with_context(|| format!("read native-wall raw stream {}", path.display()))?;
    kernel_stack_addresses_from_lines(contents.lines())
}

#[cfg(target_os = "macos")]
fn kernel_stack_addresses_from_lines<I, S>(lines: I) -> Result<Vec<u64>>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut addresses = std::collections::BTreeSet::new();
    let mut open_stack = None::<StackTraceRecord>;
    for (index, raw_line) in lines.into_iter().enumerate() {
        let line = raw_line.as_ref().trim();
        if line.is_empty() {
            continue;
        }
        if let Some(stack) = open_stack.as_mut() {
            if line == "NWSTACK1|end" {
                if stack.frames.is_empty() {
                    bail!("native-wall stack at line {} has no frames", index + 1);
                }
                let stack = open_stack
                    .take()
                    .ok_or_else(|| anyhow!("native-wall stack state disappeared"))?;
                if stack.state == "kernel-oncpu" {
                    for frame in stack.frames {
                        addresses.insert(raw_kernel_address(&frame)?);
                    }
                }
            } else if line.starts_with("NWSTACK1|begin") {
                bail!("nested native-wall stack at line {}", index + 1);
            } else if line.starts_with("NWSTACK1|") {
                bail!(
                    "unrecognized native-wall stack marker at line {}",
                    index + 1
                );
            } else if line.starts_with("DSRPROF1|") || line.starts_with("NWIMAGES1|") {
                bail!(
                    "profile record interrupted native-wall stack at line {}",
                    index + 1
                );
            } else {
                stack.frames.push(line.to_owned());
            }
            continue;
        }
        if line.starts_with("NWSTACK1|begin") {
            open_stack = Some(
                StackTraceRecord::begin(line)
                    .with_context(|| format!("invalid stack at line {}", index + 1))?,
            );
        } else if line == "NWSTACK1|end" {
            bail!("native-wall stack end without begin at line {}", index + 1);
        } else if line.starts_with("NWSTACK1|") {
            bail!(
                "unrecognized native-wall stack marker at line {}",
                index + 1
            );
        }
    }
    if open_stack.is_some() {
        bail!("profile stream ended inside a native-wall stack");
    }
    if addresses.is_empty() {
        bail!("native-wall stream has no raw kernel stack addresses");
    }
    Ok(addresses.into_iter().collect())
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub(crate) struct ProfileCaptureStatus {
    pub(crate) principal_drops: u64,
    pub(crate) aggregation_drops: u64,
    pub(crate) dynamic_drops: u64,
    pub(crate) other_drops: u64,
    pub(crate) interrupted: bool,
}

#[cfg(any(target_os = "macos", target_os = "freebsd"))]
impl From<carrick_runtime::dtrace_consumer::DTraceRunReport> for ProfileCaptureStatus {
    fn from(report: carrick_runtime::dtrace_consumer::DTraceRunReport) -> Self {
        Self {
            principal_drops: report.principal_drops,
            aggregation_drops: report.aggregation_drops,
            dynamic_drops: report.dynamic_drops,
            other_drops: report.other_drops,
            interrupted: report.interrupted,
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

fn summed_count(
    grouped: &BTreeMap<ProfileScope, MetricBuilder>,
    phase: &str,
    kind: Option<&str>,
) -> Result<Option<u64>> {
    let mut found = false;
    let mut total = 0_u64;
    for (scope, metric) in grouped {
        if scope.phase.as_deref() == Some(phase)
            && kind.is_none_or(|expected| scope.kind.as_deref() == Some(expected))
            && let Some(value) = metric.count
        {
            found = true;
            total = total
                .checked_add(value)
                .ok_or_else(|| anyhow!("native-wall {phase} count population overflow"))?;
        }
    }
    Ok(found.then_some(total))
}

fn summed_total_ns(grouped: &BTreeMap<ProfileScope, MetricBuilder>, phase: &str) -> Option<u64> {
    let mut found = false;
    let mut total = 0_u64;
    for (scope, metric) in grouped {
        if scope.phase.as_deref() == Some(phase)
            && let Some(value) = metric.total_ns
        {
            found = true;
            total = total.saturating_add(value);
        }
    }
    found.then_some(total)
}

fn validate_native_wall_metrics(
    grouped: &BTreeMap<ProfileScope, MetricBuilder>,
    stack_traces: &[StackTraceRecord],
) -> Result<()> {
    let wall_samples = summed_count(grouped, "wall-samples", None)?
        .filter(|value| *value != 0)
        .ok_or_else(|| anyhow!("native-wall profile has no wall samples"))?;
    let wall_buckets = summed_count(grouped, "wall-state", None)?
        .ok_or_else(|| anyhow!("native-wall profile has no wall-state buckets"))?;
    if wall_buckets != wall_samples {
        bail!("native-wall wall-state buckets sum to {wall_buckets}, expected {wall_samples}");
    }
    summed_total_ns(grouped, "elapsed")
        .filter(|value| *value != 0)
        .ok_or_else(|| anyhow!("native-wall profile has no elapsed duration"))?;
    let live_at_end = summed_count(grouped, "process-lifecycle", Some("live-at-end"))?
        .ok_or_else(|| anyhow!("native-wall profile has no live-at-end count"))?;
    if live_at_end != 0 {
        bail!("native-wall profile ended with {live_at_end} tracked process(es)");
    }
    let kernel_samples = summed_count(grouped, "cpu-kernel-pc", None)?.unwrap_or(0);
    let mut kernel_stack_samples = 0_u64;
    let mut has_kernel_stacks = false;
    let mut has_voluntary_stacks = false;
    for stack in stack_traces {
        match stack.value {
            StackTraceValue::Count(value) => {
                has_kernel_stacks = true;
                kernel_stack_samples = kernel_stack_samples
                    .checked_add(value)
                    .ok_or_else(|| anyhow!("native-wall kernel stack population overflow"))?;
            }
            StackTraceValue::DurationNs(_) => {
                has_voluntary_stacks = true;
            }
        }
    }
    if has_kernel_stacks && kernel_stack_samples != kernel_samples {
        bail!(
            "native-wall kernel stack samples total {kernel_stack_samples}, expected {kernel_samples}"
        );
    }
    if summed_count(grouped, "cpu-user-pc", None)?.unwrap_or(0) == 0 && kernel_samples == 0 {
        bail!("native-wall profile has no CPU samples");
    }
    let voluntary_ns = summed_total_ns(grouped, "offcpu-voluntary-total").unwrap_or(0);
    if voluntary_ns != 0 && !has_voluntary_stacks {
        bail!("native-wall profile has voluntary off-CPU time but no blocking stacks");
    }
    Ok(())
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
    ImageCatalog {
        pid: u64,
        ranges: Vec<HostImageRangeRecord>,
    },
    #[cfg(target_os = "macos")]
    KernelIdentity {
        snapshot_schema: &'static str,
        identity: KernelIdentity,
    },
    #[cfg(target_os = "macos")]
    KernelObjectCatalog {
        snapshot_schema: &'static str,
        objects: Vec<KernelObjectRange>,
    },
    #[cfg(target_os = "macos")]
    KernelSymbolMap {
        snapshot_schema: &'static str,
        symbols: Vec<KernelSymbolRange>,
    },
    StackTrace {
        state: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        pid: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        count: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        value_ns: Option<u64>,
        frames: Vec<String>,
    },
    Completion,
}

#[derive(Clone, Copy, Debug, Serialize)]
pub(crate) struct CompletionState {
    complete: bool,
    bounded: bool,
    target_exit_reason: u64,
    high_cardinality_overflow: bool,
    incomplete_pairs: u64,
    cardinality: ProfileCardinality,
    drops: ProfileCaptureStatus,
}

#[derive(Clone, Copy, Debug, Default, Serialize)]
pub(crate) struct ProfileCardinality {
    indirect_sources: u64,
    indirect_pairs: u64,
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
        let mut stack_traces = Vec::<StackTraceRecord>::new();
        let mut image_catalogs = BTreeMap::<u64, Vec<HostImageRangeRecord>>::new();
        let mut open_stack = None::<StackTraceRecord>;
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
            if let Some(stack) = open_stack.as_mut() {
                if line == "NWSTACK1|end" {
                    let stack = open_stack
                        .take()
                        .ok_or_else(|| anyhow!("native-wall stack state disappeared"))?;
                    if stack.frames.is_empty() {
                        bail!("native-wall stack at line {} has no frames", index + 1);
                    }
                    stack_traces.push(stack);
                } else if line.starts_with("NWSTACK1|begin") {
                    bail!("nested native-wall stack at line {}", index + 1);
                } else if line.starts_with("DSRPROF1|") {
                    bail!(
                        "profile record interrupted native-wall stack at line {}",
                        index + 1
                    );
                } else {
                    stack.frames.push(line.to_owned());
                }
                continue;
            }
            if line.starts_with("NWSTACK1|begin") {
                open_stack = Some(
                    StackTraceRecord::begin(line)
                        .with_context(|| format!("invalid stack at line {}", index + 1))?,
                );
                continue;
            }
            if line == "NWSTACK1|end" {
                bail!("native-wall stack end without begin at line {}", index + 1);
            }
            if line.starts_with("NWIMAGES1|") {
                let catalog = HostImageCatalogRecord::parse(line)
                    .with_context(|| format!("invalid image catalog at line {}", index + 1))?;
                match image_catalogs.entry(catalog.pid) {
                    Entry::Vacant(slot) => {
                        slot.insert(catalog.ranges);
                    }
                    Entry::Occupied(_) => {
                        bail!("duplicate image catalog for pid {}", catalog.pid);
                    }
                }
                continue;
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
                // macOS proc:::exit arg0 is the CLD_* reason. CLD_EXITED is 1;
                // signal termination (for example an interrupted trace) is not
                // a successful profile completion. Default old DSRPROF1 streams
                // to CLD_EXITED so checked-in pre-field evidence remains readable.
                let target_exit_reason = record.optional_u64("target_exit_reason")?.unwrap_or(1);
                completion = Some((profile, bounded, target_exit_reason));
                continue;
            }

            let scope = ProfileScope::from_record(&record)?;
            match record.record_type {
                RecordType::Count => {
                    let value = record.required_u64("value")?;
                    let phase = scope.phase.as_deref().unwrap_or("<unscoped>").to_owned();
                    let builder = grouped.entry(scope).or_default();
                    let previous = builder.count.unwrap_or(0);
                    builder.count = Some(previous.checked_add(value).ok_or_else(|| {
                        anyhow!(
                            "profile count population overflow for phase {phase:?} at line {}",
                            index + 1
                        )
                    })?);
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
        if open_stack.is_some() {
            bail!("profile stream ended inside a native-wall stack");
        }

        let (profile, bounded, target_exit_reason) =
            completion.ok_or_else(|| anyhow!("profile stream is missing its completion record"))?;
        if !stack_traces.is_empty() && profile != TraceProfileKind::NativeWall {
            bail!("stack records are valid only for the native-wall profile");
        }
        if !image_catalogs.is_empty() && profile != TraceProfileKind::NativeWall {
            bail!("image catalogs are valid only for the native-wall profile");
        }
        if profile == TraceProfileKind::NativeWall {
            validate_native_wall_metrics(&grouped, &stack_traces)?;
        }
        for (scope, builder) in &grouped {
            let exact_fields = [
                builder.count.is_some(),
                builder.total_ns.is_some(),
                builder.minimum_ns.is_some(),
                builder.maximum_ns.is_some(),
            ];
            if scope.phase.as_deref() == Some("translation-subphase")
                && exact_fields.iter().any(|present| *present)
                && !exact_fields.iter().all(|present| *present)
            {
                bail!(
                    "translation subphase aggregate is truncated for pid={:?} kind={:?}",
                    scope.pid,
                    scope.kind
                );
            }
        }
        let incomplete_pairs = grouped.values().fold(0_u64, |total, builder| {
            total.saturating_add(builder.incomplete)
        });
        let has_metrics = !grouped.is_empty() || !high_water.is_empty();
        let cardinality = ProfileCardinality {
            indirect_sources: u64::try_from(
                grouped
                    .keys()
                    .filter(|scope| {
                        scope.phase.as_deref() == Some("indirect-source")
                            && scope.source_pc.is_some()
                    })
                    .count(),
            )
            .unwrap_or(u64::MAX),
            indirect_pairs: u64::try_from(
                grouped
                    .keys()
                    .filter(|scope| {
                        scope.phase.as_deref() == Some("indirect-pair")
                            && scope.source_pc.is_some()
                            && scope.target_pc.is_some()
                    })
                    .count(),
            )
            .unwrap_or(u64::MAX),
        };
        let completion = CompletionState {
            complete: !bounded
                && target_exit_reason == 1
                && has_metrics
                && !capture_status.interrupted
                && incomplete_pairs == 0
                && capture_status.aggregation_drops == 0
                && capture_status.dynamic_drops == 0
                && capture_status.other_drops == 0,
            bounded,
            target_exit_reason,
            high_cardinality_overflow: capture_status.aggregation_drops != 0
                || capture_status.dynamic_drops != 0,
            incomplete_pairs,
            cardinality,
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
        for (pid, ranges) in image_catalogs {
            metrics.push(ProfileOutputMetric {
                scope: ProfileScope {
                    phase: Some("image-catalog".to_owned()),
                    pid: Some(pid),
                    tid: None,
                    kind: None,
                    source_pc: None,
                    target_pc: None,
                },
                metric: ProfileMetric::ImageCatalog { pid, ranges },
                sampling_interval: None,
            });
        }
        for stack in stack_traces {
            let (phase, scope_pid, metric_pid, count, value_ns) = match stack.value {
                StackTraceValue::Count(samples) => {
                    ("cpu-kernel-stack", None, None, Some(samples), None)
                }
                StackTraceValue::DurationNs(duration_ns) => {
                    let pid = stack
                        .pid
                        .ok_or_else(|| anyhow!("voluntary stack lost its pid"))?;
                    (
                        "offcpu-voluntary-stack",
                        Some(pid),
                        Some(pid),
                        None,
                        Some(duration_ns),
                    )
                }
            };
            metrics.push(ProfileOutputMetric {
                scope: ProfileScope {
                    phase: Some(phase.to_owned()),
                    pid: scope_pid,
                    tid: None,
                    kind: Some(stack.state.clone()),
                    source_pc: None,
                    target_pc: None,
                },
                metric: ProfileMetric::StackTrace {
                    state: stack.state,
                    pid: metric_pid,
                    count,
                    value_ns,
                    frames: stack.frames,
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

    #[cfg(target_os = "macos")]
    pub(crate) fn attach_kernel_symbol_snapshot(
        &mut self,
        snapshot: KernelSymbolSnapshot,
    ) -> Result<()> {
        if self.profile != TraceProfileKind::NativeWall {
            bail!("kernel symbol snapshots are valid only for native-wall profiles");
        }
        if self.metrics.iter().any(|metric| {
            matches!(
                metric.metric,
                ProfileMetric::KernelIdentity { .. }
                    | ProfileMetric::KernelObjectCatalog { .. }
                    | ProfileMetric::KernelSymbolMap { .. }
            )
        }) {
            bail!("kernel symbol snapshot is already attached");
        }
        snapshot
            .validate()
            .context("invalid kernel symbol snapshot")?;
        if snapshot.schema != KERNEL_SYMBOL_SCHEMA {
            bail!(
                "kernel symbol snapshot schema is {:?}, expected {KERNEL_SYMBOL_SCHEMA:?}",
                snapshot.schema
            );
        }
        let mut addresses = std::collections::BTreeSet::new();
        for metric in &self.metrics {
            if let ProfileMetric::StackTrace { state, frames, .. } = &metric.metric
                && state == "kernel-oncpu"
            {
                for frame in frames {
                    addresses.insert(raw_kernel_address(frame)?);
                }
            }
        }
        snapshot
            .reconcile_addresses(addresses)
            .context("kernel symbol snapshot does not match raw kernel stacks")?;
        let completion_index = self
            .metrics
            .iter()
            .position(|metric| matches!(metric.metric, ProfileMetric::Completion))
            .ok_or_else(|| anyhow!("profile summary lost its completion row"))?;
        let empty_scope = || ProfileScope {
            phase: None,
            pid: None,
            tid: None,
            kind: None,
            source_pc: None,
            target_pc: None,
        };
        let metadata = [
            ProfileOutputMetric {
                scope: empty_scope(),
                metric: ProfileMetric::KernelIdentity {
                    snapshot_schema: KERNEL_SYMBOL_SCHEMA,
                    identity: snapshot.identity,
                },
                sampling_interval: None,
            },
            ProfileOutputMetric {
                scope: empty_scope(),
                metric: ProfileMetric::KernelObjectCatalog {
                    snapshot_schema: KERNEL_SYMBOL_SCHEMA,
                    objects: snapshot.objects,
                },
                sampling_interval: None,
            },
            ProfileOutputMetric {
                scope: empty_scope(),
                metric: ProfileMetric::KernelSymbolMap {
                    snapshot_schema: KERNEL_SYMBOL_SCHEMA,
                    symbols: snapshot.symbols,
                },
                sampling_interval: None,
            },
        ];
        self.metrics
            .splice(completion_index..completion_index, metadata);
        Ok(())
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
            "DSR profile {}: {} metric row(s), complete={}, bounded={}, interrupted={}, target_exit_reason={}, incomplete_pairs={}, drops={}/{}/{}/{}",
            self.profile.as_str(),
            self.metrics.len().saturating_sub(1),
            self.completion.complete,
            self.completion.bounded,
            self.completion.drops.interrupted,
            self.completion.target_exit_reason,
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
    {
        let mut writer = BufWriter::new(temporary.as_file_mut());
        for row in summary.json_rows() {
            serde_json::to_writer(&mut writer, &row).context("serialize DSR profile row")?;
            writer
                .write_all(b"\n")
                .context("terminate DSR profile row")?;
        }
        writer.flush().context("flush buffered DSR profile JSONL")?;
    }
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
    #[cfg(target_os = "macos")]
    use carrick_runtime::dtrace_symbols::{
        DTRACE_OBJ_F_KERNEL, KERNEL_SYMBOL_SCHEMA, KernelIdentity, KernelObjectRange,
        KernelSymbolRange, KernelSymbolSnapshot,
    };

    #[cfg(target_os = "macos")]
    fn kernel_snapshot(addresses: &[u64]) -> KernelSymbolSnapshot {
        KernelSymbolSnapshot::from_parts(
            KernelIdentity {
                osversion: "26A5388g".to_owned(),
                version: "Darwin Kernel Version 26.0.0".to_owned(),
                uuid: "01234567-89AB-CDEF-0123-456789ABCDEF".to_owned(),
                machine: "arm64".to_owned(),
            },
            vec![KernelObjectRange {
                name: "kernel".to_owned(),
                file: Some("/System/kernel".to_owned()),
                id: 1,
                flags: DTRACE_OBJ_F_KERNEL,
                text_start: 0x1000,
                text_size: 0x1000,
            }],
            addresses
                .iter()
                .map(|address| KernelSymbolRange {
                    address: *address,
                    object: "kernel".to_owned(),
                    symbol: format!("fn_{address:x}"),
                    symbol_id: *address,
                    symbol_start: *address,
                    symbol_size: 1,
                    offset: 0,
                })
                .collect(),
            addresses.iter().copied(),
        )
        .expect("snapshot")
    }

    #[cfg(target_os = "macos")]
    fn raw_native_wall_lines() -> Vec<&'static str> {
        vec![
            "DSRPROF1|count|phase=wall-state|kind=on-cpu|value=3",
            "DSRPROF1|count|phase=wall-samples|value=3",
            "DSRPROF1|count|phase=cpu-kernel-pc|source_pc=0x1018|value=3",
            "DSRPROF1|count|phase=process-lifecycle|kind=live-at-end|value=0",
            "DSRPROF1|total|phase=elapsed|value_ns=1000000",
            "NWSTACK1|begin|state=kernel-oncpu|value=2",
            "0x1018",
            "0x1028",
            "NWSTACK1|end",
            "NWSTACK1|begin|state=kernel-oncpu|value=1",
            "0x1018",
            "0x1038",
            "NWSTACK1|end",
            "DSRPROF1|complete|profile=native-wall|bounded=0|target_exit_reason=1",
        ]
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn native_wall_raw_address_extraction_includes_all_frames_and_deduplicates() {
        assert_eq!(
            kernel_stack_addresses_from_lines(raw_native_wall_lines()).expect("addresses"),
            [0x1018, 0x1028, 0x1038]
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn native_wall_raw_address_extraction_rejects_missing_malformed_and_symbolic_frames() {
        for lines in [
            vec![
                "NWSTACK1|begin|state=kernel-oncpu|value=1",
                "kernel`symbol",
                "NWSTACK1|end",
            ],
            vec![
                "NWSTACK1|begin|state=kernel-oncpu|value=1",
                "0xnothex",
                "NWSTACK1|end",
            ],
            vec!["NWSTACK1|begin|state=kernel-oncpu|value=1", "0x1018"],
            vec!["NWSTACK1|end"],
            vec![
                "NWSTACK1|begin|state=voluntary|pid=1|value_ns=1",
                "0x1018",
                "NWSTACK1|end",
            ],
        ] {
            assert!(kernel_stack_addresses_from_lines(lines).is_err());
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn native_wall_raw_address_extraction_rejects_unknown_stack_markers() {
        for lines in [
            vec![
                "NWSTACK1|unknown",
                "NWSTACK1|begin|state=kernel-oncpu|value=1",
                "0x1018",
                "NWSTACK1|end",
            ],
            vec![
                "NWSTACK1|begin|state=voluntary|pid=1|value_ns=1",
                "NWSTACK1|unknown",
                "0x1018",
                "NWSTACK1|end",
                "NWSTACK1|begin|state=kernel-oncpu|value=1",
                "0x1018",
                "NWSTACK1|end",
            ],
        ] {
            assert!(kernel_stack_addresses_from_lines(lines).is_err());
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn native_wall_attachment_reconciles_and_serializes_exact_metadata_rows_before_completion() {
        let lines = raw_native_wall_lines();
        let mut summary =
            ProfileSummary::from_lines(lines, ProfileCaptureStatus::default()).expect("summary");
        summary
            .attach_kernel_symbol_snapshot(kernel_snapshot(&[0x1018, 0x1028, 0x1038]))
            .expect("attach");
        let rows = summary
            .json_rows()
            .into_iter()
            .map(|row| serde_json::to_value(row).expect("serialize"))
            .collect::<Vec<_>>();
        let types = rows
            .iter()
            .map(|row| row["metric"]["type"].as_str().expect("metric type"))
            .collect::<Vec<_>>();
        assert_eq!(
            &types[types.len() - 4..],
            [
                "kernel-identity",
                "kernel-object-catalog",
                "kernel-symbol-map",
                "completion",
            ]
        );
        for expected in [
            "kernel-identity",
            "kernel-object-catalog",
            "kernel-symbol-map",
        ] {
            let matching = rows
                .iter()
                .filter(|row| row["metric"]["type"] == expected)
                .collect::<Vec<_>>();
            assert_eq!(matching.len(), 1);
            assert_eq!(
                matching[0]["metric"]["snapshot_schema"],
                KERNEL_SYMBOL_SCHEMA
            );
        }
        assert_eq!(
            rows.iter()
                .filter(|row| row["metric"]["type"] == "completion")
                .count(),
            1
        );
        assert_eq!(
            rows,
            summary
                .json_rows()
                .into_iter()
                .map(|row| serde_json::to_value(row).expect("serialize"))
                .collect::<Vec<_>>()
        );
        let identity = rows
            .iter()
            .find(|row| row["metric"]["type"] == "kernel-identity")
            .expect("identity row");
        assert!(identity["metric"].get("identity").is_some());
        assert!(identity["metric"].get("objects").is_none());
        assert!(identity["metric"].get("symbols").is_none());
        let catalog = rows
            .iter()
            .find(|row| row["metric"]["type"] == "kernel-object-catalog")
            .expect("catalog row");
        assert!(catalog["metric"].get("identity").is_none());
        assert!(catalog["metric"].get("objects").is_some());
        assert!(catalog["metric"].get("symbols").is_none());
        let symbol_map = rows
            .iter()
            .find(|row| row["metric"]["type"] == "kernel-symbol-map")
            .expect("symbol-map row");
        assert!(symbol_map["metric"].get("identity").is_none());
        assert!(symbol_map["metric"].get("objects").is_none());
        assert!(symbol_map["metric"].get("symbols").is_some());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn native_wall_attachment_rejects_twice_and_address_or_range_mismatch() {
        let lines = raw_native_wall_lines();
        let mut summary =
            ProfileSummary::from_lines(&lines, ProfileCaptureStatus::default()).expect("summary");
        summary
            .attach_kernel_symbol_snapshot(kernel_snapshot(&[0x1018, 0x1028, 0x1038]))
            .expect("first attachment");
        assert!(
            summary
                .attach_kernel_symbol_snapshot(kernel_snapshot(&[0x1018, 0x1028, 0x1038]))
                .is_err()
        );

        for addresses in [vec![0x1018, 0x1028], vec![0x1018, 0x1028, 0x1038, 0x1048]] {
            let mut summary = ProfileSummary::from_lines(&lines, ProfileCaptureStatus::default())
                .expect("summary");
            assert!(
                summary
                    .attach_kernel_symbol_snapshot(kernel_snapshot(&addresses))
                    .is_err()
            );
        }

        let mut invalid_snapshots = Vec::new();
        let mut duplicate = kernel_snapshot(&[0x1018, 0x1028, 0x1038]);
        duplicate.symbols.push(duplicate.symbols[0].clone());
        invalid_snapshots.push(duplicate);
        let mut bad_offset = kernel_snapshot(&[0x1018, 0x1028, 0x1038]);
        bad_offset.symbols[0].offset = 1;
        invalid_snapshots.push(bad_offset);
        let mut bad_symbol_range = kernel_snapshot(&[0x1018, 0x1028, 0x1038]);
        bad_symbol_range.symbols[0].symbol_start = 0x2000;
        invalid_snapshots.push(bad_symbol_range);
        let mut bad_object_range = kernel_snapshot(&[0x1018, 0x1028, 0x1038]);
        bad_object_range.objects[0].text_size = 1;
        invalid_snapshots.push(bad_object_range);
        let mut bad_schema = kernel_snapshot(&[0x1018, 0x1028, 0x1038]);
        bad_schema.schema = "carrick.kernel-symbols.v0".to_owned();
        invalid_snapshots.push(bad_schema);

        for snapshot in invalid_snapshots {
            let mut summary = ProfileSummary::from_lines(&lines, ProfileCaptureStatus::default())
                .expect("summary");
            assert!(summary.attach_kernel_symbol_snapshot(snapshot).is_err());
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn kernel_snapshot_cannot_attach_to_another_profile_and_non_native_json_is_unchanged() {
        let mut summary = ProfileSummary::from_lines(
            ["DSRPROF1|complete|profile=dsr-fork|bounded=0"],
            ProfileCaptureStatus::default(),
        )
        .expect("summary");
        let before = serde_json::to_value(summary.json_rows()).expect("before");
        assert!(
            summary
                .attach_kernel_symbol_snapshot(kernel_snapshot(&[0x1018]))
                .is_err()
        );
        assert_eq!(
            serde_json::to_value(summary.json_rows()).expect("after"),
            before
        );
    }

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
    fn profiles_using_prepare_phases_require_runtime_instrumentation() {
        assert!(TraceProfileKind::Dsr.requires_runtime_profile());
        assert!(!TraceProfileKind::DsrIndirect.requires_runtime_profile());
        assert!(TraceProfileKind::DsrFork.requires_runtime_profile());
    }

    #[test]
    fn native_wall_profile_parses_reconciled_samples_and_blocking_stack() {
        assert!(!TraceProfileKind::NativeWall.requires_runtime_profile());
        let summary = ProfileSummary::from_lines(
            [
                "DSRPROF1|count|phase=wall-state|kind=on-cpu|value=120",
                "DSRPROF1|count|phase=wall-state|kind=runnable-descheduled|value=40",
                "DSRPROF1|count|phase=wall-state|kind=all-sleeping|value=35",
                "DSRPROF1|count|phase=wall-state|kind=transition|value=2",
                "DSRPROF1|count|phase=wall-samples|value=197",
                "DSRPROF1|count|phase=cpu-user-pc|pid=42|source_pc=0x1000|value=499",
                "DSRPROF1|total|phase=offcpu-voluntary-pc|pid=42|source_pc=0x2000|value_ns=1000",
                "DSRPROF1|total|phase=offcpu-voluntary-total|value_ns=1000",
                "NWSTACK1|begin|state=voluntary|pid=42|value_ns=900",
                "0x2000",
                "0x3000",
                "NWSTACK1|end",
                "DSRPROF1|count|phase=process-lifecycle|kind=live-at-end|value=0",
                "DSRPROF1|total|phase=elapsed|value_ns=1000000000",
                "DSRPROF1|complete|profile=native-wall|bounded=0|target_exit_reason=1",
            ],
            ProfileCaptureStatus::default(),
        )
        .expect("complete native wall profile");

        summary
            .require_profile(TraceProfileKind::NativeWall)
            .expect("matching profile");
        assert!(summary.completion.complete);
        let rows = summary
            .json_rows()
            .into_iter()
            .map(|row| serde_json::to_value(row).expect("serialize row"))
            .collect::<Vec<_>>();
        let voluntary = rows
            .iter()
            .find(|row| row["scope"]["phase"] == "offcpu-voluntary-stack")
            .expect("voluntary stack row");
        assert_eq!(voluntary["scope"]["pid"], 42);
        assert_eq!(voluntary["metric"]["state"], "voluntary");
        assert_eq!(voluntary["metric"]["pid"], 42);
        assert_eq!(voluntary["metric"]["value_ns"], 900);
        assert_eq!(voluntary["metric"].get("count"), None);
        assert_eq!(
            voluntary["metric"]["frames"],
            serde_json::json!(["0x2000", "0x3000"])
        );
    }

    #[test]
    fn native_wall_kernel_stacks_serialize_as_reconciled_counts() {
        // Catches rejecting count-valued kernel stacks or serializing pid/value_ns on them.
        let summary = ProfileSummary::from_lines(
            [
                "DSRPROF1|count|phase=wall-state|kind=on-cpu|value=1",
                "DSRPROF1|count|phase=wall-samples|value=1",
                "DSRPROF1|count|phase=cpu-kernel-pc|source_pc=0xfffffe0012345000|value=3",
                "DSRPROF1|count|phase=process-lifecycle|kind=live-at-end|value=0",
                "DSRPROF1|total|phase=elapsed|value_ns=1000000",
                "NWSTACK1|begin|state=kernel-oncpu|value=2",
                "kernel`foo",
                "NWSTACK1|end",
                "NWSTACK1|begin|state=kernel-oncpu|value=1",
                "kernel`bar",
                "NWSTACK1|end",
                "DSRPROF1|complete|profile=native-wall|bounded=0|target_exit_reason=1",
            ],
            ProfileCaptureStatus::default(),
        )
        .expect("complete native wall profile");

        let rows = summary
            .json_rows()
            .into_iter()
            .map(|row| serde_json::to_value(row).expect("serialize row"))
            .collect::<Vec<_>>();
        let kernel = rows
            .iter()
            .filter(|row| row["scope"]["phase"] == "cpu-kernel-stack")
            .collect::<Vec<_>>();
        assert_eq!(kernel.len(), 2);
        assert_eq!(kernel[0]["scope"].get("pid"), None);
        assert_eq!(kernel[0]["metric"].get("pid"), None);
        assert_eq!(kernel[0]["metric"]["count"], 2);
        assert_eq!(kernel[0]["metric"].get("value_ns"), None);
        assert_eq!(kernel[1]["metric"]["count"], 1);
    }

    #[test]
    fn native_wall_kernel_stacks_must_reconcile_with_kernel_pcs() {
        // Catches accepting a kernel stack population (2) unlike the kernel PC population (3).
        let error = ProfileSummary::from_lines(
            [
                "DSRPROF1|count|phase=wall-state|kind=on-cpu|value=1",
                "DSRPROF1|count|phase=wall-samples|value=1",
                "DSRPROF1|count|phase=cpu-kernel-pc|source_pc=0xfffffe0012345000|value=3",
                "DSRPROF1|count|phase=process-lifecycle|kind=live-at-end|value=0",
                "DSRPROF1|total|phase=elapsed|value_ns=1000000",
                "NWSTACK1|begin|state=kernel-oncpu|value=2",
                "kernel`foo",
                "NWSTACK1|end",
                "DSRPROF1|complete|profile=native-wall|bounded=0|target_exit_reason=1",
            ],
            ProfileCaptureStatus::default(),
        )
        .expect_err("kernel PC/stack mismatch must reject");
        assert!(
            error.to_string().contains("kernel stack samples"),
            "unexpected error: {error:#}"
        );
    }

    #[test]
    fn native_wall_stack_headers_enforce_state_dependent_fields() {
        let cases = [
            (
                "accepts both value and value_ns",
                "NWSTACK1|begin|state=kernel-oncpu|value=1|value_ns=1",
                true,
            ),
            (
                "accepts neither value nor value_ns",
                "NWSTACK1|begin|state=kernel-oncpu",
                true,
            ),
            (
                "accepts a pid on kernel-oncpu",
                "NWSTACK1|begin|state=kernel-oncpu|pid=42|value=1",
                true,
            ),
            (
                "accepts an unknown field",
                "NWSTACK1|begin|state=kernel-oncpu|unknown=1|value=1",
                true,
            ),
            (
                "accepts a duplicate field",
                "NWSTACK1|begin|state=kernel-oncpu|value=1|value=1",
                true,
            ),
            ("accepts a missing state", "NWSTACK1|begin|value=1", true),
            (
                "accepts zero kernel samples",
                "NWSTACK1|begin|state=kernel-oncpu|value=0",
                true,
            ),
            (
                "accepts voluntary stack without pid",
                "NWSTACK1|begin|state=voluntary|value_ns=1",
                true,
            ),
            (
                "accepts count-valued voluntary stack",
                "NWSTACK1|begin|state=voluntary|pid=42|value=1",
                true,
            ),
            (
                "accepts zero voluntary pid",
                "NWSTACK1|begin|state=voluntary|pid=0|value_ns=1",
                true,
            ),
            (
                "accepts zero voluntary duration",
                "NWSTACK1|begin|state=voluntary|pid=42|value_ns=0",
                true,
            ),
            (
                "accepts empty kernel frames",
                "NWSTACK1|begin|state=kernel-oncpu|value=1",
                false,
            ),
        ];

        for (mutation, header, include_frame) in cases {
            let mut lines = vec![
                "DSRPROF1|count|phase=wall-state|kind=on-cpu|value=1",
                "DSRPROF1|count|phase=wall-samples|value=1",
                "DSRPROF1|count|phase=cpu-kernel-pc|source_pc=0xfffffe0012345000|value=1",
                "DSRPROF1|count|phase=process-lifecycle|kind=live-at-end|value=0",
                "DSRPROF1|total|phase=elapsed|value_ns=1000000",
                header,
            ];
            if include_frame {
                lines.push("kernel`foo");
            }
            lines.extend([
                "NWSTACK1|end",
                "DSRPROF1|complete|profile=native-wall|bounded=0|target_exit_reason=1",
            ]);
            assert!(
                ProfileSummary::from_lines(lines, ProfileCaptureStatus::default()).is_err(),
                "production mutation {mutation:?} was not caught"
            );
        }
    }

    #[test]
    fn native_wall_historical_kernel_pcs_without_stacks_remain_valid() {
        // Catches requiring new kernel stack rows in historical profile streams.
        let summary = ProfileSummary::from_lines(
            [
                "DSRPROF1|count|phase=wall-state|kind=on-cpu|value=1",
                "DSRPROF1|count|phase=wall-samples|value=1",
                "DSRPROF1|count|phase=cpu-kernel-pc|source_pc=0xfffffe0012345000|value=3",
                "DSRPROF1|count|phase=process-lifecycle|kind=live-at-end|value=0",
                "DSRPROF1|total|phase=elapsed|value_ns=1000000",
                "DSRPROF1|complete|profile=native-wall|bounded=0|target_exit_reason=1",
            ],
            ProfileCaptureStatus::default(),
        )
        .expect("historical kernel-only native wall profile");
        assert!(
            summary
                .json_rows()
                .iter()
                .all(|row| row.scope.phase.as_deref() != Some("cpu-kernel-stack"))
        );
    }

    #[test]
    fn native_wall_zero_kernel_historical_input_remains_valid() {
        // Catches treating absent kernel samples/stacks as an evidence mismatch.
        let summary = ProfileSummary::from_lines(
            [
                "DSRPROF1|count|phase=wall-state|kind=on-cpu|value=1",
                "DSRPROF1|count|phase=wall-samples|value=1",
                "DSRPROF1|count|phase=cpu-user-pc|pid=42|source_pc=0x1000|value=1",
                "DSRPROF1|count|phase=process-lifecycle|kind=live-at-end|value=0",
                "DSRPROF1|total|phase=elapsed|value_ns=1000000",
                "DSRPROF1|complete|profile=native-wall|bounded=0|target_exit_reason=1",
            ],
            ProfileCaptureStatus::default(),
        )
        .expect("historical user-only native wall profile");
        assert!(
            summary
                .json_rows()
                .iter()
                .all(|row| row.scope.phase.as_deref() != Some("cpu-kernel-stack"))
        );
    }

    #[test]
    fn native_wall_kernel_pc_population_overflow_rejects() {
        // Catches saturating or wrapping u64::MAX + 1 while accumulating kernel PCs.
        let error = ProfileSummary::from_lines(
            [
                "DSRPROF1|count|phase=wall-state|kind=on-cpu|value=1",
                "DSRPROF1|count|phase=wall-samples|value=1",
                "DSRPROF1|count|phase=cpu-kernel-pc|source_pc=0xfffffe0012345000|value=18446744073709551615",
                "DSRPROF1|count|phase=cpu-kernel-pc|source_pc=0xfffffe0012345000|value=1",
                "DSRPROF1|count|phase=process-lifecycle|kind=live-at-end|value=0",
                "DSRPROF1|total|phase=elapsed|value_ns=1000000",
                "DSRPROF1|complete|profile=native-wall|bounded=0|target_exit_reason=1",
            ],
            ProfileCaptureStatus::default(),
        )
        .expect_err("kernel PC overflow must reject");
        assert!(
            error.to_string().contains("overflow"),
            "unexpected error: {error:#}"
        );
    }

    #[test]
    fn native_wall_kernel_stack_population_overflow_rejects() {
        // Catches saturating, wrapping, or panicking on u64::MAX + 1 kernel stacks.
        let error = ProfileSummary::from_lines(
            [
                "DSRPROF1|count|phase=wall-state|kind=on-cpu|value=1",
                "DSRPROF1|count|phase=wall-samples|value=1",
                "DSRPROF1|count|phase=cpu-kernel-pc|source_pc=0xfffffe0012345000|value=18446744073709551615",
                "DSRPROF1|count|phase=process-lifecycle|kind=live-at-end|value=0",
                "DSRPROF1|total|phase=elapsed|value_ns=1000000",
                "NWSTACK1|begin|state=kernel-oncpu|value=18446744073709551615",
                "kernel`foo",
                "NWSTACK1|end",
                "NWSTACK1|begin|state=kernel-oncpu|value=1",
                "kernel`bar",
                "NWSTACK1|end",
                "DSRPROF1|complete|profile=native-wall|bounded=0|target_exit_reason=1",
            ],
            ProfileCaptureStatus::default(),
        )
        .expect_err("kernel stack overflow must reject");
        assert!(
            error.to_string().contains("overflow"),
            "unexpected error: {error:#}"
        );
    }

    fn assert_native_wall_count_overflow(lines: Vec<&str>, phase: &str, mutation: &str) {
        let error = ProfileSummary::from_lines(lines, ProfileCaptureStatus::default())
            .expect_err("validation count overflow must reject");
        let message = error.to_string();
        assert!(
            message.contains(phase) && message.contains("overflow"),
            "production mutation {mutation:?} produced unexpected error: {error:#}"
        );
    }

    #[test]
    fn native_wall_cpu_user_pc_per_scope_overflow_rejects() {
        assert_native_wall_count_overflow(
            vec![
                "DSRPROF1|count|phase=wall-state|kind=on-cpu|value=1",
                "DSRPROF1|count|phase=wall-samples|value=1",
                "DSRPROF1|count|phase=cpu-user-pc|pid=42|source_pc=0x1000|value=18446744073709551615",
                "DSRPROF1|count|phase=cpu-user-pc|pid=42|source_pc=0x1000|value=1",
                "DSRPROF1|count|phase=process-lifecycle|kind=live-at-end|value=0",
                "DSRPROF1|total|phase=elapsed|value_ns=1000000",
                "DSRPROF1|complete|profile=native-wall|bounded=0|target_exit_reason=1",
            ],
            "cpu-user-pc",
            "saturates one cpu-user-pc scope",
        );
    }

    #[test]
    fn native_wall_wall_samples_per_scope_overflow_rejects() {
        assert_native_wall_count_overflow(
            vec![
                "DSRPROF1|count|phase=wall-state|kind=on-cpu|value=18446744073709551615",
                "DSRPROF1|count|phase=wall-samples|value=18446744073709551615",
                "DSRPROF1|count|phase=wall-samples|value=1",
                "DSRPROF1|count|phase=cpu-user-pc|pid=42|source_pc=0x1000|value=1",
                "DSRPROF1|count|phase=process-lifecycle|kind=live-at-end|value=0",
                "DSRPROF1|total|phase=elapsed|value_ns=1000000",
                "DSRPROF1|complete|profile=native-wall|bounded=0|target_exit_reason=1",
            ],
            "wall-samples",
            "saturates one wall-samples scope",
        );
    }

    #[test]
    fn native_wall_wall_state_per_scope_overflow_rejects() {
        assert_native_wall_count_overflow(
            vec![
                "DSRPROF1|count|phase=wall-state|kind=on-cpu|value=18446744073709551615",
                "DSRPROF1|count|phase=wall-state|kind=on-cpu|value=1",
                "DSRPROF1|count|phase=wall-samples|value=18446744073709551615",
                "DSRPROF1|count|phase=cpu-user-pc|pid=42|source_pc=0x1000|value=1",
                "DSRPROF1|count|phase=process-lifecycle|kind=live-at-end|value=0",
                "DSRPROF1|total|phase=elapsed|value_ns=1000000",
                "DSRPROF1|complete|profile=native-wall|bounded=0|target_exit_reason=1",
            ],
            "wall-state",
            "saturates one wall-state scope",
        );
    }

    #[test]
    fn native_wall_process_lifecycle_per_scope_overflow_rejects() {
        assert_native_wall_count_overflow(
            vec![
                "DSRPROF1|count|phase=wall-state|kind=on-cpu|value=1",
                "DSRPROF1|count|phase=wall-samples|value=1",
                "DSRPROF1|count|phase=cpu-user-pc|pid=42|source_pc=0x1000|value=1",
                "DSRPROF1|count|phase=process-lifecycle|kind=live-at-end|value=18446744073709551615",
                "DSRPROF1|count|phase=process-lifecycle|kind=live-at-end|value=1",
                "DSRPROF1|total|phase=elapsed|value_ns=1000000",
                "DSRPROF1|complete|profile=native-wall|bounded=0|target_exit_reason=1",
            ],
            "process-lifecycle",
            "saturates one process-lifecycle scope",
        );
    }

    #[test]
    fn native_wall_cpu_user_pc_population_overflow_rejects() {
        assert_native_wall_count_overflow(
            vec![
                "DSRPROF1|count|phase=wall-state|kind=on-cpu|value=1",
                "DSRPROF1|count|phase=wall-samples|value=1",
                "DSRPROF1|count|phase=cpu-user-pc|pid=42|source_pc=0x1000|value=18446744073709551615",
                "DSRPROF1|count|phase=cpu-user-pc|pid=43|source_pc=0x2000|value=1",
                "DSRPROF1|count|phase=process-lifecycle|kind=live-at-end|value=0",
                "DSRPROF1|total|phase=elapsed|value_ns=1000000",
                "DSRPROF1|complete|profile=native-wall|bounded=0|target_exit_reason=1",
            ],
            "cpu-user-pc",
            "saturates the cpu-user-pc population across scopes",
        );
    }

    #[test]
    fn native_wall_wall_samples_population_overflow_rejects() {
        assert_native_wall_count_overflow(
            vec![
                "DSRPROF1|count|phase=wall-state|kind=on-cpu|value=18446744073709551615",
                "DSRPROF1|count|phase=wall-samples|kind=first|value=18446744073709551615",
                "DSRPROF1|count|phase=wall-samples|kind=second|value=1",
                "DSRPROF1|count|phase=cpu-user-pc|pid=42|source_pc=0x1000|value=1",
                "DSRPROF1|count|phase=process-lifecycle|kind=live-at-end|value=0",
                "DSRPROF1|total|phase=elapsed|value_ns=1000000",
                "DSRPROF1|complete|profile=native-wall|bounded=0|target_exit_reason=1",
            ],
            "wall-samples",
            "saturates the wall-samples population across scopes",
        );
    }

    #[test]
    fn native_wall_wall_state_population_overflow_rejects() {
        assert_native_wall_count_overflow(
            vec![
                "DSRPROF1|count|phase=wall-state|kind=on-cpu|value=18446744073709551615",
                "DSRPROF1|count|phase=wall-state|kind=transition|value=1",
                "DSRPROF1|count|phase=wall-samples|value=18446744073709551615",
                "DSRPROF1|count|phase=cpu-user-pc|pid=42|source_pc=0x1000|value=1",
                "DSRPROF1|count|phase=process-lifecycle|kind=live-at-end|value=0",
                "DSRPROF1|total|phase=elapsed|value_ns=1000000",
                "DSRPROF1|complete|profile=native-wall|bounded=0|target_exit_reason=1",
            ],
            "wall-state",
            "saturates the wall-state population across scopes",
        );
    }

    #[test]
    fn native_wall_process_lifecycle_population_overflow_rejects() {
        assert_native_wall_count_overflow(
            vec![
                "DSRPROF1|count|phase=wall-state|kind=on-cpu|value=1",
                "DSRPROF1|count|phase=wall-samples|value=1",
                "DSRPROF1|count|phase=cpu-user-pc|pid=42|source_pc=0x1000|value=1",
                "DSRPROF1|count|phase=process-lifecycle|kind=live-at-end|pid=42|value=18446744073709551615",
                "DSRPROF1|count|phase=process-lifecycle|kind=live-at-end|pid=43|value=1",
                "DSRPROF1|total|phase=elapsed|value_ns=1000000",
                "DSRPROF1|complete|profile=native-wall|bounded=0|target_exit_reason=1",
            ],
            "process-lifecycle",
            "saturates the process-lifecycle population across scopes",
        );
    }

    #[test]
    fn native_wall_profile_parses_host_image_catalog() {
        let summary = ProfileSummary::from_lines(
            [
                "DSRPROF1|count|phase=wall-state|kind=on-cpu|value=120",
                "DSRPROF1|count|phase=wall-samples|value=120",
                "DSRPROF1|count|phase=cpu-user-pc|pid=42|source_pc=0x1000|value=499",
                "DSRPROF1|count|phase=process-lifecycle|kind=live-at-end|value=0",
                "DSRPROF1|total|phase=elapsed|value_ns=1000000000",
                "NWIMAGES1|{\"ok\":{\"pid\":42,\"ranges\":[{\"start\":32768,\"end\":40960,\"path\":\"/usr/lib/libSystem.B.dylib\"}]}}",
                "DSRPROF1|complete|profile=native-wall|bounded=0|target_exit_reason=1",
            ],
            ProfileCaptureStatus::default(),
        )
        .expect("complete native wall profile");

        assert!(summary.metrics.iter().any(|output| matches!(
            &output.metric,
            ProfileMetric::ImageCatalog { pid: 42, ranges }
                if ranges.len() == 1
                    && ranges[0].start == 32_768
                    && ranges[0].end == 40_960
                    && ranges[0].path == "/usr/lib/libSystem.B.dylib"
        )));
    }

    #[test]
    fn native_wall_profile_rejects_unreconciled_populations() {
        let cases = [
            (
                "missing elapsed duration",
                vec![
                    "DSRPROF1|count|phase=wall-state|kind=on-cpu|value=10",
                    "DSRPROF1|count|phase=wall-samples|value=10",
                    "DSRPROF1|count|phase=cpu-user-pc|pid=42|source_pc=0x1000|value=5",
                    "DSRPROF1|count|phase=process-lifecycle|kind=live-at-end|value=0",
                    "DSRPROF1|complete|profile=native-wall|bounded=0|target_exit_reason=1",
                ],
            ),
            (
                "wall bucket mismatch",
                vec![
                    "DSRPROF1|count|phase=wall-state|kind=on-cpu|value=9",
                    "DSRPROF1|count|phase=wall-samples|value=10",
                    "DSRPROF1|count|phase=cpu-user-pc|pid=42|source_pc=0x1000|value=5",
                    "DSRPROF1|count|phase=process-lifecycle|kind=live-at-end|value=0",
                    "DSRPROF1|total|phase=elapsed|value_ns=1000",
                    "DSRPROF1|complete|profile=native-wall|bounded=0|target_exit_reason=1",
                ],
            ),
            (
                "live process at end",
                vec![
                    "DSRPROF1|count|phase=wall-state|kind=on-cpu|value=10",
                    "DSRPROF1|count|phase=wall-samples|value=10",
                    "DSRPROF1|count|phase=cpu-user-pc|pid=42|source_pc=0x1000|value=5",
                    "DSRPROF1|count|phase=process-lifecycle|kind=live-at-end|value=1",
                    "DSRPROF1|total|phase=elapsed|value_ns=1000",
                    "DSRPROF1|complete|profile=native-wall|bounded=0|target_exit_reason=1",
                ],
            ),
            (
                "missing CPU sample",
                vec![
                    "DSRPROF1|count|phase=wall-state|kind=on-cpu|value=10",
                    "DSRPROF1|count|phase=wall-samples|value=10",
                    "DSRPROF1|count|phase=process-lifecycle|kind=live-at-end|value=0",
                    "DSRPROF1|total|phase=elapsed|value_ns=1000",
                    "DSRPROF1|complete|profile=native-wall|bounded=0|target_exit_reason=1",
                ],
            ),
            (
                "voluntary time without stack",
                vec![
                    "DSRPROF1|count|phase=wall-state|kind=on-cpu|value=10",
                    "DSRPROF1|count|phase=wall-samples|value=10",
                    "DSRPROF1|count|phase=cpu-user-pc|pid=42|source_pc=0x1000|value=5",
                    "DSRPROF1|count|phase=process-lifecycle|kind=live-at-end|value=0",
                    "DSRPROF1|total|phase=elapsed|value_ns=1000",
                    "DSRPROF1|total|phase=offcpu-voluntary-total|value_ns=500",
                    "DSRPROF1|complete|profile=native-wall|bounded=0|target_exit_reason=1",
                ],
            ),
        ];

        for (case, lines) in cases {
            assert!(
                ProfileSummary::from_lines(lines, ProfileCaptureStatus::default()).is_err(),
                "{case} was accepted"
            );
        }
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
    fn empty_profile_stream_cannot_be_complete() {
        let summary = ProfileSummary::from_lines(
            ["DSRPROF1|complete|profile=dsr|bounded=0|target_exit_reason=1"],
            ProfileCaptureStatus::default(),
        )
        .expect("syntactically valid empty profile");
        assert!(!summary.completion.complete);
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
    fn translation_subphase_aggregates_fail_closed_when_truncated() {
        assert!(
            ProfileSummary::from_lines(
                [
                    "DSRPROF1|count|phase=translation-subphase|pid=10|kind=1|value=9",
                    "DSRPROF1|complete|profile=dsr|bounded=0",
                ],
                ProfileCaptureStatus::default(),
            )
            .is_err()
        );

        let summary = ProfileSummary::from_lines(
            [
                "DSRPROF1|count|phase=translation-subphase|pid=10|kind=1|value=9",
                "DSRPROF1|total|phase=translation-subphase|pid=10|kind=1|value_ns=90000",
                "DSRPROF1|minimum|phase=translation-subphase|pid=10|kind=1|value_ns=7000",
                "DSRPROF1|maximum|phase=translation-subphase|pid=10|kind=1|value_ns=15000",
                "DSRPROF1|complete|profile=dsr|bounded=0",
            ],
            ProfileCaptureStatus::default(),
        )
        .expect("complete translation subphase");
        assert!(summary.completion.complete);
    }

    #[test]
    fn parses_hex_guest_pcs_and_marks_aggregation_loss_incomplete() {
        let status = ProfileCaptureStatus {
            aggregation_drops: 2,
            ..ProfileCaptureStatus::default()
        };
        let summary = ProfileSummary::from_lines(
            [
                "DSRPROF1|count|phase=indirect-source|pid=10|source_pc=0x4000|value=12",
                "DSRPROF1|count|phase=indirect-pair|pid=10|source_pc=0x4000|target_pc=0x8000|value=7",
                "DSRPROF1|complete|profile=dsr-indirect|bounded=0",
            ],
            status,
        )
        .expect("profile summary");
        assert!(!summary.completion.complete);
        assert!(summary.completion.high_cardinality_overflow);
        assert_eq!(summary.completion.cardinality.indirect_sources, 1);
        assert_eq!(summary.completion.cardinality.indirect_pairs, 1);
        assert!(summary.metrics.iter().any(|metric| {
            metric.scope.source_pc == Some(0x4000) && metric.scope.target_pc.is_none()
        }));
        assert!(summary.metrics.iter().any(|metric| {
            metric.scope.source_pc == Some(0x4000) && metric.scope.target_pc == Some(0x8000)
        }));
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
    fn signaled_target_exit_cannot_complete_a_profile() {
        let summary = ProfileSummary::from_lines(
            ["DSRPROF1|complete|profile=dsr|bounded=0|target_exit_reason=2"],
            ProfileCaptureStatus::default(),
        )
        .expect("signaled profile summary");
        assert!(!summary.completion.complete);
        assert_eq!(summary.completion.target_exit_reason, 2);
    }

    #[test]
    fn interrupted_capture_cannot_complete_a_profile() {
        let summary = ProfileSummary::from_lines(
            ["DSRPROF1|complete|profile=dsr|bounded=0|target_exit_reason=1"],
            ProfileCaptureStatus {
                interrupted: true,
                ..ProfileCaptureStatus::default()
            },
        )
        .expect("interrupted profile summary");
        assert!(!summary.completion.complete);
        assert!(summary.completion.drops.interrupted);
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
    fn fork_lifecycle_samples_and_open_pair_survive_parsing() {
        let summary = ProfileSummary::from_lines(
            [
                "DSRPROF1|sample|phase=fork-child-repair|pid=21|tid=21|duration_ns=1200",
                "DSRPROF1|sample|phase=first-prepare-after-fork|pid=21|tid=21|duration_ns=800",
                "DSRPROF1|sample|phase=host-self-reexec|pid=21|tid=21|duration_ns=1100",
                "DSRPROF1|sample|phase=exec-reset|pid=21|tid=21|duration_ns=900",
                "DSRPROF1|sample|phase=first-prepare-after-exec|pid=21|tid=21|duration_ns=700",
                "DSRPROF1|incomplete|phase=exec-reset|pid=21|tid=21|kind=open|value=1",
                "DSRPROF1|complete|profile=dsr-fork|bounded=0",
            ],
            ProfileCaptureStatus::default(),
        )
        .expect("fork profile");
        assert_eq!(
            summary
                .metrics
                .iter()
                .filter(|metric| matches!(metric.metric, ProfileMetric::SampledDuration { .. }))
                .count(),
            5
        );
        assert_eq!(summary.completion.incomplete_pairs, 1);
        assert!(!summary.completion.complete);
    }

    #[test]
    fn prepared_self_reexec_lifecycle_survives_parsing_without_legacy_load() {
        let summary = ProfileSummary::from_lines(
            [
                "DSRPROF1|sample|phase=host-self-reexec-prepared-build|pid=21|tid=21|duration_ns=1200",
                "DSRPROF1|sample|phase=host-self-reexec-prepared-validate|pid=21|tid=21|duration_ns=800",
                "DSRPROF1|sample|phase=host-self-reexec-prepared-map|pid=21|tid=21|duration_ns=700",
                "DSRPROF1|complete|profile=dsr-fork|bounded=0|target_exit_reason=1",
            ],
            ProfileCaptureStatus::default(),
        )
        .expect("prepared profile");
        let phases = summary
            .metrics
            .iter()
            .filter_map(|metric| metric.scope.phase.as_deref())
            .collect::<Vec<_>>();
        assert_eq!(
            phases,
            [
                "host-self-reexec-prepared-build",
                "host-self-reexec-prepared-map",
                "host-self-reexec-prepared-validate",
            ]
        );
        assert!(!phases.contains(&"host-self-reexec-image-load"));
        assert!(summary.completion.complete);
    }

    #[test]
    fn fallback_self_reexec_lifecycle_survives_parsing_without_prepared_map() {
        let summary = ProfileSummary::from_lines(
            [
                "DSRPROF1|sample|phase=host-self-reexec-prepared-build|pid=21|tid=21|duration_ns=900",
                "DSRPROF1|sample|phase=host-self-reexec-image-load|pid=21|tid=21|duration_ns=1700",
                "DSRPROF1|complete|profile=dsr-fork|bounded=0|target_exit_reason=1",
            ],
            ProfileCaptureStatus::default(),
        )
        .expect("fallback profile");
        let phases = summary
            .metrics
            .iter()
            .filter_map(|metric| metric.scope.phase.as_deref())
            .collect::<Vec<_>>();
        assert_eq!(
            phases,
            [
                "host-self-reexec-image-load",
                "host-self-reexec-prepared-build",
            ]
        );
        assert!(!phases.contains(&"host-self-reexec-prepared-map"));
        assert_eq!(summary.completion.incomplete_pairs, 0);
        assert!(summary.completion.complete);
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
