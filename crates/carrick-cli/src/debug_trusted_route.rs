//! `carrick debug trusted-route-census` — validate and join a lossless DTrace
//! PC histogram with process-retirement JIT snapshots.
//!
//! This command is deliberately offline. DTrace establishes sampled-PC
//! population and loss state; the retiring process exports immutable code and
//! typed route geometry; this module authenticates both inputs before it
//! attributes any sample. A plausible partial join is an error, not evidence.

use std::collections::BTreeMap;
use std::fs;
use std::io::{BufWriter, Write};
use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;

use crate::trace_profile::{TrustedRouteCaptureReceipt, TrustedRoutePcRow, parse_trusted_route_pc};

const REPORT_SCHEMA: &str = "carrick.trusted-route-census.v1";
const SNAPSHOT_SCHEMA: &str = "carrick.code-snapshot.v2";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub(crate) struct RouteTallies {
    pub(crate) fallthrough: u64,
    pub(crate) direct: u64,
    pub(crate) indirect: u64,
}

impl RouteTallies {
    fn total(self) -> Result<u64> {
        self.fallthrough
            .checked_add(self.direct)
            .and_then(|total| total.checked_add(self.indirect))
            .ok_or_else(|| anyhow!("trusted-route tally overflow"))
    }

    fn add(&mut self, route: Route, samples: u64) -> Result<()> {
        let slot = match route {
            Route::Fallthrough => &mut self.fallthrough,
            Route::Direct => &mut self.direct,
            Route::Indirect => &mut self.indirect,
        };
        *slot = slot
            .checked_add(samples)
            .ok_or_else(|| anyhow!("trusted-route sample population overflow"))?;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize)]
pub(crate) struct RouteShares {
    pub(crate) fallthrough: f64,
    pub(crate) direct: f64,
    pub(crate) indirect: f64,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub(crate) struct TrustedRouteCensusReport {
    pub(crate) schema: &'static str,
    pub(crate) trace_sha256: String,
    pub(crate) capture_sha256: String,
    pub(crate) snapshots_sha256: String,
    pub(crate) total_pc_samples: u64,
    pub(crate) matched_samples: u64,
    pub(crate) missing_pid_samples: u64,
    pub(crate) missing_range_samples: u64,
    pub(crate) routes: RouteTallies,
    pub(crate) artificial_branches: RouteTallies,
    pub(crate) route_shares: RouteShares,
    pub(crate) jit_share: f64,
    pub(crate) projected_total_cpu: RouteShares,
    pub(crate) sequence_bytes: u32,
    /// Diagnostic trusted-entry rows, one per instrumented published block.
    pub(crate) block_count: u64,
    pub(crate) validation_failures: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Route {
    Fallthrough,
    Direct,
    Indirect,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SnapshotIndex {
    schema: String,
    pid: u32,
    cache_base: u64,
    code_len: usize,
    code_sha256: String,
    blocks: Vec<(u64, u64)>,
    trusted_routes: Vec<SnapshotRoute>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SnapshotRoute {
    guest_start: u64,
    generation: u64,
    fallthrough: std::ops::Range<u64>,
    direct: std::ops::Range<u64>,
    indirect: std::ops::Range<u64>,
    fallthrough_branch: u64,
    direct_branch: u64,
    indirect_branch: u64,
    common_body: u64,
}

struct LoadedSnapshot {
    index: SnapshotIndex,
    cache_end: u64,
}

struct SnapshotSet {
    by_pid: BTreeMap<u32, LoadedSnapshot>,
    sha256: String,
    sequence_bytes: u32,
    block_count: u64,
}

pub(crate) fn run_trusted_route_census(
    trace: &Path,
    capture: &Path,
    snapshots: &Path,
    jit_share: f64,
    output: Option<&Path>,
) -> Result<()> {
    let report = build_trusted_route_census(trace, capture, snapshots, jit_share)?;
    let mut rendered =
        serde_json::to_vec_pretty(&report).context("serialize trusted-route census")?;
    rendered.push(b'\n');
    let report_sha256 = format!("{:x}", Sha256::digest(&rendered));
    if let Some(path) = output {
        write_atomic(path, &rendered)?;
        eprintln!(
            "trusted-route census: output={} sha256={report_sha256}",
            path.display()
        );
    } else {
        std::io::stdout()
            .write_all(&rendered)
            .context("write trusted-route census to stdout")?;
    }
    if !report.validation_failures.is_empty() {
        bail!(
            "trusted-route census has {} validation failure(s)",
            report.validation_failures.len()
        );
    }
    Ok(())
}

pub(crate) fn build_trusted_route_census(
    trace_path: &Path,
    capture_path: &Path,
    snapshots_path: &Path,
    jit_share: f64,
) -> Result<TrustedRouteCensusReport> {
    validate_jit_share(jit_share)?;
    let trace = fs::read(trace_path)
        .with_context(|| format!("read trusted-route trace {}", trace_path.display()))?;
    let capture = fs::read(capture_path)
        .with_context(|| format!("read trusted-route receipt {}", capture_path.display()))?;
    let receipt: TrustedRouteCaptureReceipt = serde_json::from_slice(&capture)
        .with_context(|| format!("parse trusted-route receipt {}", capture_path.display()))?;
    let authenticated =
        TrustedRouteCaptureReceipt::from_bytes(&trace, receipt.drops, receipt.provenance.clone())
            .context("revalidate trusted-route raw trace against receipt contract")?;
    if authenticated != receipt {
        bail!("trusted-route receipt does not exactly match the raw trace and current D program");
    }
    let snapshot_set = load_snapshots(snapshots_path)?;
    let trace_text = std::str::from_utf8(&trace).context("trusted-route trace is not UTF-8")?;
    let mut rows = Vec::new();
    for (line_index, raw_line) in trace_text.lines().enumerate() {
        let line = raw_line.trim();
        if line.starts_with("PC ") {
            rows.push(
                parse_trusted_route_pc(line)
                    .with_context(|| format!("malformed PC row at line {}", line_index + 1))?,
            );
        }
    }
    let row_count = u64::try_from(rows.len()).context("trusted-route PC row count exceeds u64")?;
    let total_pc_samples = rows.iter().try_fold(0_u64, |total, row| {
        total
            .checked_add(row.samples)
            .ok_or_else(|| anyhow!("trusted-route PC population overflow"))
    })?;
    if row_count != receipt.pc_rows || total_pc_samples != receipt.pc_samples {
        bail!(
            "trusted-route receipt population mismatch: rows={row_count}/{}, samples={total_pc_samples}/{}",
            receipt.pc_rows,
            receipt.pc_samples
        );
    }

    let mut matched_samples = 0_u64;
    let mut missing_pid_samples = 0_u64;
    let mut missing_range_samples = 0_u64;
    let mut routes = RouteTallies::default();
    let mut artificial_branches = RouteTallies::default();
    for row in rows {
        let Some(snapshot) = snapshot_set.by_pid.get(&row.pid) else {
            missing_pid_samples =
                checked_add_population(missing_pid_samples, row.samples, "missing-PID samples")?;
            continue;
        };
        if row.pc < snapshot.index.cache_base || row.pc >= snapshot.cache_end {
            missing_range_samples = checked_add_population(
                missing_range_samples,
                row.samples,
                "missing-range samples",
            )?;
            continue;
        }
        matched_samples = checked_add_population(matched_samples, row.samples, "matched samples")?;
        if let Some((route, branch)) = classify_route(&snapshot.index.trusted_routes, row) {
            if branch {
                artificial_branches.add(route, row.samples)?;
            } else {
                routes.add(route, row.samples)?;
            }
        }
    }
    let reconciled = matched_samples
        .checked_add(missing_pid_samples)
        .and_then(|total| total.checked_add(missing_range_samples))
        .ok_or_else(|| anyhow!("trusted-route classified population overflow"))?;
    if reconciled != total_pc_samples {
        bail!("trusted-route classification did not conserve the PC population");
    }

    let route_total = routes.total()?;
    let mut validation_failures = Vec::new();
    if route_total == 0 {
        validation_failures.push("zero trusted-route sequence samples".to_owned());
    }
    if missing_pid_samples != 0 {
        validation_failures.push(format!(
            "{missing_pid_samples} sample(s) name a PID without one snapshot commit marker"
        ));
    }
    if missing_range_samples != 0 {
        validation_failures.push(format!(
            "{missing_range_samples} sample(s) fall outside their PID snapshot cache range"
        ));
    }
    let route_shares = shares(routes, route_total);
    let projected_total_cpu = projected(routes, total_pc_samples, jit_share);
    Ok(TrustedRouteCensusReport {
        schema: REPORT_SCHEMA,
        trace_sha256: format!("{:x}", Sha256::digest(&trace)),
        capture_sha256: format!("{:x}", Sha256::digest(&capture)),
        snapshots_sha256: snapshot_set.sha256,
        total_pc_samples,
        matched_samples,
        missing_pid_samples,
        missing_range_samples,
        routes,
        artificial_branches,
        route_shares,
        jit_share,
        projected_total_cpu,
        sequence_bytes: snapshot_set.sequence_bytes,
        block_count: snapshot_set.block_count,
        validation_failures,
    })
}

fn validate_jit_share(jit_share: f64) -> Result<()> {
    if !jit_share.is_finite() || jit_share <= 0.0 || jit_share > 1.0 {
        bail!("--jit-share must be finite and in (0, 1], got {jit_share:?}");
    }
    Ok(())
}

fn checked_add_population(current: u64, add: u64, name: &str) -> Result<u64> {
    current
        .checked_add(add)
        .ok_or_else(|| anyhow!("{name} overflow"))
}

fn shares(routes: RouteTallies, total: u64) -> RouteShares {
    if total == 0 {
        return RouteShares::default();
    }
    let denominator = total as f64;
    RouteShares {
        fallthrough: routes.fallthrough as f64 / denominator,
        direct: routes.direct as f64 / denominator,
        indirect: routes.indirect as f64 / denominator,
    }
}

fn projected(routes: RouteTallies, total_pc_samples: u64, jit_share: f64) -> RouteShares {
    if total_pc_samples == 0 {
        return RouteShares::default();
    }
    let scale = jit_share / total_pc_samples as f64;
    RouteShares {
        fallthrough: routes.fallthrough as f64 * scale,
        direct: routes.direct as f64 * scale,
        indirect: routes.indirect as f64 * scale,
    }
}

fn classify_route(routes: &[SnapshotRoute], row: TrustedRoutePcRow) -> Option<(Route, bool)> {
    let candidate = routes
        .partition_point(|route| route.fallthrough.start <= row.pc)
        .checked_sub(1)
        .and_then(|index| routes.get(index))?;
    for (kind, span, branch) in [
        (
            Route::Fallthrough,
            &candidate.fallthrough,
            candidate.fallthrough_branch,
        ),
        (Route::Direct, &candidate.direct, candidate.direct_branch),
        (
            Route::Indirect,
            &candidate.indirect,
            candidate.indirect_branch,
        ),
    ] {
        if span.contains(&row.pc) {
            return Some((kind, false));
        }
        if row.pc == branch {
            return Some((kind, true));
        }
    }
    None
}

fn load_snapshots(directory: &Path) -> Result<SnapshotSet> {
    let mut indexes = fs::read_dir(directory)
        .with_context(|| format!("read snapshot directory {}", directory.display()))?
        .map(|entry| entry.map(|value| value.path()))
        .collect::<std::io::Result<Vec<_>>>()?;
    indexes.retain(|path| {
        path.extension()
            .is_some_and(|extension| extension == "json")
    });
    indexes.sort();
    if indexes.is_empty() {
        bail!("snapshot directory has no JSON commit markers");
    }

    let mut by_pid = BTreeMap::new();
    let mut manifest = Vec::new();
    let mut sequence_bytes = None;
    let mut block_count = 0_u64;
    for index_path in indexes {
        let index_name = index_path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| anyhow!("snapshot index has a non-UTF-8 filename"))?;
        let code_path = index_path.with_extension("bin");
        if !code_path.is_file() {
            bail!(
                "snapshot commit marker {} has no paired .bin",
                index_path.display()
            );
        }
        let index_bytes = fs::read(&index_path)
            .with_context(|| format!("read snapshot index {}", index_path.display()))?;
        let code = fs::read(&code_path)
            .with_context(|| format!("read snapshot code {}", code_path.display()))?;
        let index: SnapshotIndex = serde_json::from_slice(&index_bytes)
            .with_context(|| format!("parse snapshot index {}", index_path.display()))?;
        if index.schema != SNAPSHOT_SCHEMA {
            bail!(
                "snapshot {} has schema {:?}",
                index_path.display(),
                index.schema
            );
        }
        if index.code_len != code.len() {
            bail!(
                "snapshot {} code length is {}, expected {}",
                index_path.display(),
                code.len(),
                index.code_len
            );
        }
        let code_sha256 = format!("{:x}", Sha256::digest(&code));
        if index.code_sha256 != code_sha256 {
            bail!("snapshot {} code SHA-256 mismatch", index_path.display());
        }
        let cache_end = index
            .cache_base
            .checked_add(u64::try_from(index.code_len).context("snapshot code length exceeds u64")?)
            .ok_or_else(|| anyhow!("snapshot cache range overflow"))?;
        let observed_sequence_bytes = validate_snapshot(&index, &code, cache_end)
            .with_context(|| format!("validate snapshot {}", index_path.display()))?;
        if let Some(observed) = observed_sequence_bytes {
            match sequence_bytes {
                Some(expected) if expected != observed => bail!(
                    "snapshot route sequence width changed from {expected} to {observed} bytes"
                ),
                None => sequence_bytes = Some(observed),
                Some(_) => {}
            }
        }
        block_count = block_count
            .checked_add(
                u64::try_from(index.trusted_routes.len())
                    .context("snapshot trusted-route count exceeds u64")?,
            )
            .ok_or_else(|| anyhow!("snapshot trusted-route count overflow"))?;
        if by_pid
            .insert(index.pid, LoadedSnapshot { index, cache_end })
            .is_some()
        {
            bail!("PID has duplicate snapshot JSON commit markers");
        }
        let code_name = code_path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| anyhow!("snapshot code has a non-UTF-8 filename"))?;
        writeln!(
            &mut manifest,
            "json {index_name} {:x}",
            Sha256::digest(&index_bytes)
        )?;
        writeln!(&mut manifest, "bin {code_name} {code_sha256}")?;
    }
    Ok(SnapshotSet {
        by_pid,
        sha256: format!("{:x}", Sha256::digest(&manifest)),
        sequence_bytes: sequence_bytes.unwrap_or(0),
        block_count,
    })
}

fn validate_snapshot(index: &SnapshotIndex, code: &[u8], cache_end: u64) -> Result<Option<u32>> {
    if !code.len().is_multiple_of(4) {
        bail!("snapshot code length is not instruction aligned");
    }
    for &(guest, entry) in &index.blocks {
        if entry < index.cache_base || entry >= cache_end || !entry.is_multiple_of(4) {
            bail!("block for guest 0x{guest:x} has invalid cache entry 0x{entry:x}");
        }
    }
    let mut sequence_bytes = None;
    let mut previous_indirect_branch = None;
    for route in &index.trusted_routes {
        if !index
            .blocks
            .iter()
            .any(|(guest, _)| *guest == route.guest_start)
        {
            bail!(
                "trusted route guest 0x{:x} generation {} has no block",
                route.guest_start,
                route.generation
            );
        }
        let width = validate_span(
            &route.fallthrough,
            index.cache_base,
            cache_end,
            "fallthrough",
        )?;
        for (name, span) in [("direct", &route.direct), ("indirect", &route.indirect)] {
            if validate_span(span, index.cache_base, cache_end, name)? != width {
                bail!("trusted route sequence widths differ");
            }
        }
        if let Some(expected) = sequence_bytes {
            if expected != width {
                bail!("trusted route sequence width changed within snapshot");
            }
        } else {
            sequence_bytes = Some(width);
        }
        if route.fallthrough_branch != route.fallthrough.end
            || route.direct_branch != route.direct.end
            || route.indirect_branch != route.indirect.end
        {
            bail!("trusted route branch PC does not follow its sequence");
        }
        if route
            .fallthrough_branch
            .checked_add(4)
            .is_none_or(|next| next != route.direct.start)
            || route
                .direct_branch
                .checked_add(4)
                .is_none_or(|next| next != route.indirect.start)
            || route
                .indirect_branch
                .checked_add(4)
                .is_none_or(|next| next != route.common_body)
        {
            bail!("trusted route spans are not strictly ordered around one common body");
        }
        if route.common_body < index.cache_base
            || route.common_body >= cache_end
            || !route.common_body.is_multiple_of(4)
        {
            bail!("trusted route common body is outside the snapshot cache");
        }
        if previous_indirect_branch.is_some_and(|previous| previous >= route.fallthrough.start) {
            bail!("trusted route spans overlap");
        }
        previous_indirect_branch = Some(route.indirect_branch);

        let fallthrough = span_bytes(code, index.cache_base, &route.fallthrough)?;
        let direct = span_bytes(code, index.cache_base, &route.direct)?;
        let indirect = span_bytes(code, index.cache_base, &route.indirect)?;
        if fallthrough != direct || fallthrough != indirect {
            bail!("trusted route sequences differ");
        }
        for (name, branch) in [
            ("fallthrough", route.fallthrough_branch),
            ("direct", route.direct_branch),
            ("indirect", route.indirect_branch),
        ] {
            validate_branch(code, index.cache_base, branch, route.common_body)
                .with_context(|| format!("invalid {name} route branch"))?;
        }
    }
    Ok(sequence_bytes)
}

fn validate_span(
    span: &std::ops::Range<u64>,
    cache_base: u64,
    cache_end: u64,
    name: &str,
) -> Result<u32> {
    if span.start < cache_base
        || span.start >= span.end
        || span.end > cache_end
        || !span.start.is_multiple_of(4)
        || !span.end.is_multiple_of(4)
    {
        bail!("trusted {name} route span is invalid or outside the snapshot cache");
    }
    u32::try_from(span.end - span.start).context("trusted route span exceeds u32")
}

fn span_bytes<'a>(
    code: &'a [u8],
    cache_base: u64,
    span: &std::ops::Range<u64>,
) -> Result<&'a [u8]> {
    let start = usize::try_from(span.start - cache_base).context("route start exceeds usize")?;
    let end = usize::try_from(span.end - cache_base).context("route end exceeds usize")?;
    code.get(start..end)
        .ok_or_else(|| anyhow!("trusted route span is outside code bytes"))
}

fn validate_branch(code: &[u8], cache_base: u64, branch: u64, expected: u64) -> Result<()> {
    let offset = usize::try_from(branch - cache_base).context("branch offset exceeds usize")?;
    let bytes = code
        .get(offset..offset + 4)
        .ok_or_else(|| anyhow!("route branch is outside code bytes"))?;
    let word = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    if word & 0xfc00_0000 != 0x1400_0000 {
        bail!("route branch is not an unconditional B instruction");
    }
    let signed_words = (((word & 0x03ff_ffff) << 6) as i32 >> 6) as i64;
    let target = i128::from(branch) + i128::from(signed_words) * 4;
    if target != i128::from(expected) {
        bail!("route branch targets 0x{target:x}, expected 0x{expected:x}");
    }
    Ok(())
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent)
        .with_context(|| format!("create trusted-route output directory {}", parent.display()))?;
    let mut temporary = NamedTempFile::new_in(parent)
        .with_context(|| format!("create temporary census in {}", parent.display()))?;
    {
        let mut writer = BufWriter::new(temporary.as_file_mut());
        writer
            .write_all(bytes)
            .context("write trusted-route census")?;
        writer.flush().context("flush trusted-route census")?;
    }
    temporary
        .as_file()
        .sync_all()
        .context("sync trusted-route census")?;
    temporary.persist(path).map_err(|error| {
        anyhow!(
            "publish trusted-route census {}: {}",
            path.display(),
            error.error
        )
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace_profile::{
        ProfileCaptureStatus, ProfileProvenance, TrustedRouteCaptureReceipt,
    };
    use std::path::PathBuf;

    struct Fixture {
        _temp: tempfile::TempDir,
        trace: PathBuf,
        capture: PathBuf,
        snapshots: PathBuf,
    }

    fn words() -> Vec<u32> {
        vec![
            0xd280_00f1,
            0xf902_3f91,
            0xf942_3791,
            0x1400_0009,
            0xd280_00f1,
            0xf902_3f91,
            0xf942_3791,
            0x1400_0005,
            0xd280_00f1,
            0xf902_3f91,
            0xf942_3791,
            0x1400_0001,
            0xd503_201f,
        ]
    }

    fn bytes(words: &[u32]) -> Vec<u8> {
        words.iter().flat_map(|word| word.to_le_bytes()).collect()
    }

    fn snapshot_value(pid: u32, base: u64, code: &[u8]) -> serde_json::Value {
        serde_json::json!({
            "schema": SNAPSHOT_SCHEMA,
            "pid": pid,
            "cache_base": base,
            "code_len": code.len(),
            "code_sha256": format!("{:x}", Sha256::digest(code)),
            "blocks": [[0x40_0000_u64 + u64::from(pid), base]],
            "trusted_routes": [{
                "guest_start": 0x40_0000_u64 + u64::from(pid),
                "generation": 7,
                "fallthrough": {"start": base, "end": base + 12},
                "direct": {"start": base + 16, "end": base + 28},
                "indirect": {"start": base + 32, "end": base + 44},
                "fallthrough_branch": base + 12,
                "direct_branch": base + 28,
                "indirect_branch": base + 44,
                "common_body": base + 48
            }]
        })
    }

    fn write_snapshot(directory: &Path, pid: u32, base: u64) {
        let code = bytes(&words());
        fs::write(directory.join(format!("{pid}.bin")), &code).expect("snapshot code");
        fs::write(
            directory.join(format!("{pid}.json")),
            serde_json::to_vec(&snapshot_value(pid, base, &code)).expect("snapshot JSON"),
        )
        .expect("snapshot index");
    }

    fn raw_trace(rows: &[(u32, u64, u64)]) -> String {
        let pc_samples = rows.iter().map(|row| row.2).sum::<u64>();
        let mut raw = format!(
            "SHAPE1|section=totals\nSHAPE1|samples={}\nSHAPE1|copyin-errors=0\nSHAPE1|section=region\nSHAPE1|region=jit-or-guest|count={pc_samples}\nSHAPE1|section=pc\n",
            pc_samples + 91
        );
        for &(pid, pc, samples) in rows {
            raw.push_str(&format!("PC {pid} 0x{pc:x} {samples}\n"));
        }
        raw.push_str("SHAPE1|complete|bounded=0|target_completed=1|target_exit_reason=1\n");
        raw
    }

    fn provenance() -> ProfileProvenance {
        ProfileProvenance {
            run_id: "census-test".to_owned(),
            git_sha: "abc".to_owned(),
            git_dirty: Some(false),
            binary_sha256: "def".to_owned(),
            command: vec!["run-elf".to_owned(), "fixture".to_owned()],
            host: "test-host".to_owned(),
        }
    }

    fn write_capture(trace: &Path, capture: &Path, raw: &str) {
        fs::write(trace, raw).expect("raw trace");
        let receipt = TrustedRouteCaptureReceipt::from_bytes(
            raw.as_bytes(),
            ProfileCaptureStatus::default(),
            provenance(),
        )
        .expect("capture receipt");
        fs::write(capture, serde_json::to_vec(&receipt).expect("receipt JSON"))
            .expect("capture receipt file");
    }

    fn make_fixture(rows: &[(u32, u64, u64)]) -> Fixture {
        let temp = tempfile::tempdir().expect("fixture tempdir");
        let trace = temp.path().join("trace.raw");
        let capture = temp.path().join("capture.json");
        let snapshots = temp.path().join("snapshots");
        fs::create_dir(&snapshots).expect("snapshot directory");
        write_snapshot(&snapshots, 42, 0x1000);
        write_snapshot(&snapshots, 43, 0x2000);
        write_capture(&trace, &capture, &raw_trace(rows));
        Fixture {
            _temp: temp,
            trace,
            capture,
            snapshots,
        }
    }

    fn valid_rows() -> Vec<(u32, u64, u64)> {
        vec![
            (42, 0x1000, 10),
            (42, 0x100c, 1),
            (42, 0x1010, 20),
            (42, 0x101c, 2),
            (42, 0x1020, 30),
            (42, 0x102c, 3),
            (42, 0x1030, 10),
            (43, 0x2000, 4),
            (43, 0x200c, 4),
            (43, 0x2010, 6),
            (43, 0x201c, 5),
            (43, 0x2020, 8),
            (43, 0x202c, 6),
        ]
    }

    #[test]
    fn trusted_route_census_reports_exact_two_pid_route_populations() {
        let fixture = make_fixture(&valid_rows());

        let report =
            build_trusted_route_census(&fixture.trace, &fixture.capture, &fixture.snapshots, 0.45)
                .expect("valid census");

        assert_eq!(report.schema, REPORT_SCHEMA);
        assert_eq!(report.total_pc_samples, 109);
        assert_eq!(report.matched_samples, 109);
        assert_eq!(report.missing_pid_samples, 0);
        assert_eq!(report.missing_range_samples, 0);
        assert_eq!(
            report.routes,
            RouteTallies {
                fallthrough: 14,
                direct: 26,
                indirect: 38,
            }
        );
        assert_eq!(
            report.artificial_branches,
            RouteTallies {
                fallthrough: 5,
                direct: 7,
                indirect: 9,
            }
        );
        assert!((report.route_shares.direct - 26.0 / 78.0).abs() < 1e-12);
        assert!((report.projected_total_cpu.indirect - 38.0 * 0.45 / 109.0).abs() < 1e-12);
        assert_eq!(report.sequence_bytes, 12);
        assert_eq!(report.block_count, 2);
        assert!(report.validation_failures.is_empty());
    }

    #[test]
    fn trusted_route_census_reports_missing_pid_range_and_zero_route_samples() {
        let rows = [(99, 0x1000, 3), (42, 0x5000, 5), (42, 0x1030, 7)];
        let fixture = make_fixture(&rows);

        let report =
            build_trusted_route_census(&fixture.trace, &fixture.capture, &fixture.snapshots, 0.45)
                .expect("coverage failures remain reportable");

        assert_eq!(report.missing_pid_samples, 3);
        assert_eq!(report.missing_range_samples, 5);
        assert_eq!(report.matched_samples, 7);
        assert_eq!(report.routes, RouteTallies::default());
        assert_eq!(report.validation_failures.len(), 3);
    }

    #[test]
    fn trusted_route_census_atomically_exports_success_and_failure_reports() {
        let fixture = make_fixture(&valid_rows());
        let output = fixture._temp.path().join("report.json");
        run_trusted_route_census(
            &fixture.trace,
            &fixture.capture,
            &fixture.snapshots,
            0.45,
            Some(&output),
        )
        .expect("valid census export");
        let report: serde_json::Value =
            serde_json::from_slice(&fs::read(&output).expect("published report"))
                .expect("report JSON");
        assert_eq!(report["schema"], REPORT_SCHEMA);
        assert_eq!(report["validation_failures"], serde_json::json!([]));

        let failing = make_fixture(&[(99, 0x1000, 3)]);
        let failure_output = failing._temp.path().join("failure-report.json");
        assert!(
            run_trusted_route_census(
                &failing.trace,
                &failing.capture,
                &failing.snapshots,
                0.45,
                Some(&failure_output),
            )
            .is_err()
        );
        let report: serde_json::Value =
            serde_json::from_slice(&fs::read(failure_output).expect("published failure report"))
                .expect("failure report JSON");
        assert_eq!(
            report["validation_failures"].as_array().map(Vec::len),
            Some(2)
        );
    }

    #[test]
    fn trusted_route_census_rejects_nonpositive_or_nonfinite_jit_share() {
        for share in [0.0, -0.1, f64::NAN, 1.01] {
            assert!(validate_jit_share(share).is_err(), "accepted {share:?}");
        }
        assert!(validate_jit_share(0.46505).is_ok());
        assert!(validate_jit_share(1.0).is_ok());
    }

    #[test]
    fn trusted_route_census_rejects_missing_duplicate_or_mismatched_snapshot_payloads() {
        let fixture = make_fixture(&valid_rows());
        fs::remove_file(fixture.snapshots.join("42.bin")).expect("remove paired code");
        assert!(
            build_trusted_route_census(&fixture.trace, &fixture.capture, &fixture.snapshots, 0.45,)
                .is_err()
        );

        let fixture = make_fixture(&valid_rows());
        fs::copy(
            fixture.snapshots.join("42.json"),
            fixture.snapshots.join("42-copy.json"),
        )
        .expect("duplicate index");
        fs::copy(
            fixture.snapshots.join("42.bin"),
            fixture.snapshots.join("42-copy.bin"),
        )
        .expect("duplicate code");
        assert!(
            build_trusted_route_census(&fixture.trace, &fixture.capture, &fixture.snapshots, 0.45,)
                .is_err()
        );

        let fixture = make_fixture(&valid_rows());
        let code_path = fixture.snapshots.join("42.bin");
        let mut code = fs::read(&code_path).expect("code");
        code[0] ^= 1;
        fs::write(code_path, code).expect("corrupt code");
        assert!(
            build_trusted_route_census(&fixture.trace, &fixture.capture, &fixture.snapshots, 0.45,)
                .is_err()
        );
    }

    fn rewrite_snapshot_code(fixture: &Fixture, offset: usize) {
        let code_path = fixture.snapshots.join("42.bin");
        let index_path = fixture.snapshots.join("42.json");
        let mut code = fs::read(&code_path).expect("code");
        code[offset] ^= 1;
        fs::write(&code_path, &code).expect("mutated code");
        let mut index: serde_json::Value =
            serde_json::from_slice(&fs::read(&index_path).expect("index")).expect("index JSON");
        index["code_sha256"] = serde_json::Value::String(format!("{:x}", Sha256::digest(&code)));
        fs::write(index_path, serde_json::to_vec(&index).expect("index JSON"))
            .expect("updated index");
    }

    #[test]
    fn trusted_route_census_rejects_overlap_unequal_words_and_bad_branches() {
        let fixture = make_fixture(&valid_rows());
        let index_path = fixture.snapshots.join("42.json");
        let mut index: serde_json::Value =
            serde_json::from_slice(&fs::read(&index_path).expect("index")).expect("index JSON");
        let duplicate = index["trusted_routes"][0].clone();
        index["trusted_routes"]
            .as_array_mut()
            .expect("routes")
            .push(duplicate);
        fs::write(index_path, serde_json::to_vec(&index).expect("index JSON"))
            .expect("overlapping index");
        assert!(
            build_trusted_route_census(&fixture.trace, &fixture.capture, &fixture.snapshots, 0.45,)
                .is_err()
        );

        let fixture = make_fixture(&valid_rows());
        rewrite_snapshot_code(&fixture, 16);
        assert!(
            build_trusted_route_census(&fixture.trace, &fixture.capture, &fixture.snapshots, 0.45,)
                .is_err()
        );

        let fixture = make_fixture(&valid_rows());
        rewrite_snapshot_code(&fixture, 12);
        assert!(
            build_trusted_route_census(&fixture.trace, &fixture.capture, &fixture.snapshots, 0.45,)
                .is_err()
        );
    }

    #[test]
    fn trusted_route_census_revalidates_malformed_and_lossy_capture_receipts() {
        let fixture = make_fixture(&valid_rows());
        let malformed = fs::read_to_string(&fixture.trace)
            .expect("trace")
            .replace("PC 42 0x1000 10", "PC malformed");
        fs::write(&fixture.trace, &malformed).expect("malformed trace");
        let mut receipt: TrustedRouteCaptureReceipt =
            serde_json::from_slice(&fs::read(&fixture.capture).expect("receipt"))
                .expect("receipt JSON");
        receipt.raw_trace_sha256 = format!("{:x}", Sha256::digest(malformed.as_bytes()));
        fs::write(
            &fixture.capture,
            serde_json::to_vec(&receipt).expect("receipt JSON"),
        )
        .expect("updated receipt");
        assert!(
            build_trusted_route_census(&fixture.trace, &fixture.capture, &fixture.snapshots, 0.45,)
                .is_err()
        );

        let fixture = make_fixture(&valid_rows());
        let mut receipt: TrustedRouteCaptureReceipt =
            serde_json::from_slice(&fs::read(&fixture.capture).expect("receipt"))
                .expect("receipt JSON");
        receipt.drops.aggregation_drops = 1;
        fs::write(
            &fixture.capture,
            serde_json::to_vec(&receipt).expect("receipt JSON"),
        )
        .expect("lossy receipt");
        assert!(
            build_trusted_route_census(&fixture.trace, &fixture.capture, &fixture.snapshots, 0.45,)
                .is_err()
        );

        let fixture = make_fixture(&valid_rows());
        let mut receipt: TrustedRouteCaptureReceipt =
            serde_json::from_slice(&fs::read(&fixture.capture).expect("receipt"))
                .expect("receipt JSON");
        receipt.drops.interrupted = true;
        fs::write(
            &fixture.capture,
            serde_json::to_vec(&receipt).expect("receipt JSON"),
        )
        .expect("interrupted receipt");
        assert!(
            build_trusted_route_census(&fixture.trace, &fixture.capture, &fixture.snapshots, 0.45,)
                .is_err()
        );

        let fixture = make_fixture(&valid_rows());
        let erroneous = fs::read_to_string(&fixture.trace)
            .expect("trace")
            .replace("copyin-errors=0", "copyin-errors=1");
        fs::write(&fixture.trace, &erroneous).expect("erroneous trace");
        let mut receipt: TrustedRouteCaptureReceipt =
            serde_json::from_slice(&fs::read(&fixture.capture).expect("receipt"))
                .expect("receipt JSON");
        receipt.raw_trace_sha256 = format!("{:x}", Sha256::digest(erroneous.as_bytes()));
        receipt.copyin_errors = 1;
        fs::write(
            &fixture.capture,
            serde_json::to_vec(&receipt).expect("receipt JSON"),
        )
        .expect("error receipt");
        assert!(
            build_trusted_route_census(&fixture.trace, &fixture.capture, &fixture.snapshots, 0.45,)
                .is_err()
        );
    }
}
