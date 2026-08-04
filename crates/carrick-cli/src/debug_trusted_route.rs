//! `carrick debug trusted-route-census` — validate and join a lossless DTrace
//! PC histogram with process-retirement JIT snapshots.
//!
//! This command is deliberately offline. DTrace establishes sampled-PC
//! population and loss state; the retiring process exports immutable code and
//! typed route geometry; this module authenticates both inputs before it
//! attributes any sample. A plausible partial join is an error, not evidence.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs;
use std::io::{BufWriter, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;

use crate::trace_profile::{TrustedRouteCaptureReceipt, TrustedRoutePcRow, parse_trusted_route_pc};

const REPORT_SCHEMA: &str = "carrick.trusted-route-census.v2";
const SNAPSHOT_SCHEMA: &str = "carrick.code-snapshot.v3";

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

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub(crate) struct OriginTallies {
    pub(crate) owned: u64,
    pub(crate) unit_replay: u64,
}

impl OriginTallies {
    fn add(&mut self, origin: SnapshotOrigin, samples: u64) -> Result<()> {
        let slot = match origin {
            SnapshotOrigin::Owned => &mut self.owned,
            SnapshotOrigin::UnitReplay => &mut self.unit_replay,
        };
        *slot = slot
            .checked_add(samples)
            .ok_or_else(|| anyhow!("trusted-route origin population overflow"))?;
        Ok(())
    }
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
    pub(crate) route_origins: OriginTallies,
    pub(crate) route_samples_by_origin: OriginTallies,
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
    origin: SnapshotOrigin,
    fallthrough: std::ops::Range<u64>,
    direct: std::ops::Range<u64>,
    indirect: std::ops::Range<u64>,
    fallthrough_branch: u64,
    direct_branch: u64,
    indirect_branch: u64,
    common_body: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum SnapshotOrigin {
    Owned,
    UnitReplay,
}

struct LoadedSnapshot {
    index: SnapshotIndex,
    cache_end: u64,
}

struct SnapshotSet {
    by_pid: BTreeMap<u32, Vec<LoadedSnapshot>>,
    sha256: String,
    sequence_bytes: u32,
    block_count: u64,
    route_origins: OriginTallies,
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
    let mut route_samples_by_origin = OriginTallies::default();
    for row in rows {
        let Some(snapshots) = snapshot_set.by_pid.get(&row.pid) else {
            missing_pid_samples =
                checked_add_population(missing_pid_samples, row.samples, "missing-PID samples")?;
            continue;
        };
        let snapshot = snapshots
            .partition_point(|snapshot| snapshot.index.cache_base <= row.pc)
            .checked_sub(1)
            .and_then(|index| snapshots.get(index))
            .filter(|snapshot| row.pc < snapshot.cache_end);
        let Some(snapshot) = snapshot else {
            missing_range_samples = checked_add_population(
                missing_range_samples,
                row.samples,
                "missing-range samples",
            )?;
            continue;
        };
        matched_samples = checked_add_population(matched_samples, row.samples, "matched samples")?;
        if let Some((route, branch, origin)) = classify_route(&snapshot.index.trusted_routes, row) {
            if branch {
                artificial_branches.add(route, row.samples)?;
            } else {
                routes.add(route, row.samples)?;
                route_samples_by_origin.add(origin, row.samples)?;
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
            "{missing_pid_samples} sample(s) name a PID without a snapshot commit marker"
        ));
    }
    if missing_range_samples != 0 {
        validation_failures.push(format!(
            "{missing_range_samples} sample(s) fall outside their PID snapshot cache range"
        ));
    }
    if snapshot_set.route_origins.owned == 0 {
        validation_failures.push("snapshot set has zero owned trusted-route spans".to_owned());
    }
    if snapshot_set.route_origins.unit_replay == 0 {
        validation_failures
            .push("snapshot set has zero unit-replay trusted-route spans".to_owned());
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
        route_origins: snapshot_set.route_origins,
        route_samples_by_origin,
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

fn classify_route(
    routes: &[SnapshotRoute],
    row: TrustedRoutePcRow,
) -> Option<(Route, bool, SnapshotOrigin)> {
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
            return Some((kind, false, candidate.origin));
        }
        if row.pc == branch {
            return Some((kind, true, candidate.origin));
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
    let mut route_origins = OriginTallies::default();
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
        for route in &index.trusted_routes {
            route_origins.add(route.origin, 1)?;
        }
        by_pid
            .entry(index.pid)
            .or_insert_with(Vec::new)
            .push(LoadedSnapshot { index, cache_end });
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
    for (pid, snapshots) in &mut by_pid {
        snapshots.sort_by_key(|snapshot| snapshot.index.cache_base);
        if snapshots
            .windows(2)
            .any(|pair| pair[0].cache_end > pair[1].index.cache_base)
        {
            bail!("PID {pid} has overlapping snapshot cache ranges");
        }
    }
    Ok(SnapshotSet {
        by_pid,
        sha256: format!("{:x}", Sha256::digest(&manifest)),
        sequence_bytes: sequence_bytes.unwrap_or(0),
        block_count,
        route_origins,
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

const CAPTURE_ENV_REMOVE: &[&str] = &[
    "CARRICK_DSR_ARTIFACT_MIN_SOURCE_WORDS",
    "CARRICK_DSR_ARTIFACT_REPORT",
    "CARRICK_DSR_ARTIFACT_SPIKE",
    "CARRICK_DSR_ARTIFACT_VALIDATE_FRESH",
    "CARRICK_DSR_BASELINE_BIN",
    "CARRICK_DSR_BASELINE_COMMIT",
    "CARRICK_DSR_CANDIDATE_BIN",
    "CARRICK_DSR_CANDIDATE_COMMIT",
    "CARRICK_DSR_CODE_SNAPSHOT_DIR",
    "CARRICK_DSR_COMPACT_BIASED",
    "CARRICK_DSR_DIRECT_BINDINGS",
    "CARRICK_DSR_DIRECT_BYTES",
    "CARRICK_DSR_ENABLED_CYCLES",
    "CARRICK_DSR_ENABLED_OUT",
    "CARRICK_DSR_GATEWAY_OUT",
    "CARRICK_DSR_HIT_OUT",
    "CARRICK_DSR_KEEP_CONTAINER_CACHE",
    "CARRICK_DSR_LEAN_GUARD",
    "CARRICK_DSR_LINK_SEVER",
    "CARRICK_DSR_OBJDUMP",
    "CARRICK_DSR_OPTIMIZATION_OUT",
    "CARRICK_DSR_OVERHEAD_COOLDOWN_MS",
    "CARRICK_DSR_PERSISTENT_STORE",
    "CARRICK_DSR_PROFILE",
    "CARRICK_DSR_RESERVED_SCRATCH",
    "CARRICK_DSR_SCAN_CORPUS",
    "CARRICK_DSR_SCAN_ELF",
    "CARRICK_DSR_SHARED_DYLIB_KEYED_IDENTITY",
    "CARRICK_DSR_SHARED_MANIFEST_ARC",
    "CARRICK_DSR_SHARED_MANIFEST_FIXED",
    "CARRICK_DSR_SHARED_MAPPED_METADATA",
    "CARRICK_DSR_SHARED_RECOVERY_LAZY",
    "CARRICK_DSR_SHARED_RECOVERY_RUNS",
    "CARRICK_DSR_SHARED_SOURCE_FINGERPRINT_REUSE",
    "CARRICK_DSR_SHARED_TRANSLATION",
    "CARRICK_DSR_SUPERBLOCK",
    "CARRICK_DSR_TRUSTED_ROUTE_SPLIT",
    "CARRICK_DSR_ZERO_FAST",
    "CARRICK_EXEC_FAST",
    "CARRICK_EXEC_FILE_BACKED",
    "CARRICK_FAST_FS",
    "CARRICK_NATIVE_PAGE_PROFILE",
    "CARRICK_XLAT_CENSUS_DIR",
];

#[derive(Clone, Debug, PartialEq, Eq)]
struct CaptureEnvironment {
    set: BTreeMap<&'static str, OsString>,
    remove: Vec<&'static str>,
}

fn capture_environment(store: &Path, snapshots: Option<&Path>) -> CaptureEnvironment {
    let mut set = BTreeMap::from([
        ("CARRICK_DSR_STORE_DIR", store.as_os_str().to_owned()),
        ("CARRICK_DSR_TRUSTED_ROUTE_SPLIT", OsString::from("1")),
    ]);
    if let Some(snapshots) = snapshots {
        set.insert(
            "CARRICK_DSR_CODE_SNAPSHOT_DIR",
            snapshots.as_os_str().to_owned(),
        );
    }
    CaptureEnvironment {
        set,
        remove: CAPTURE_ENV_REMOVE.to_vec(),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CapturePhase {
    Warmup,
    Trace,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CaptureCommandSpec {
    phase: CapturePhase,
    args: Vec<String>,
    environment: CaptureEnvironment,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CaptureExit {
    success: bool,
    code: Option<i32>,
}

#[derive(Clone, Debug)]
struct CensusRequest {
    trace: PathBuf,
    capture: PathBuf,
    snapshots: PathBuf,
    jit_share: f64,
    output: PathBuf,
}

trait CaptureOps {
    fn run_command(&mut self, executable: &Path, spec: &CaptureCommandSpec) -> Result<CaptureExit>;
    fn run_census(&mut self, request: &CensusRequest) -> Result<()>;
}

struct SystemCaptureOps;

impl CaptureOps for SystemCaptureOps {
    fn run_command(&mut self, executable: &Path, spec: &CaptureCommandSpec) -> Result<CaptureExit> {
        let mut command = Command::new(executable);
        command.args(&spec.args);
        for key in &spec.environment.remove {
            command.env_remove(key);
        }
        for (key, value) in &spec.environment.set {
            command.env(key, value);
        }
        let status = command.status().with_context(|| {
            format!(
                "run trusted-route {} command via {}",
                match spec.phase {
                    CapturePhase::Warmup => "warmup",
                    CapturePhase::Trace => "trace",
                },
                executable.display()
            )
        })?;
        Ok(CaptureExit {
            success: status.success(),
            code: status.code(),
        })
    }

    fn run_census(&mut self, request: &CensusRequest) -> Result<()> {
        run_trusted_route_census(
            &request.trace,
            &request.capture,
            &request.snapshots,
            request.jit_share,
            Some(&request.output),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct StoreAuthority {
    device: u64,
    inode: u64,
    sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct StoreFile {
    path: String,
    bytes: u64,
    device: u64,
    inode: u64,
    sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct StoreManifest {
    schema: &'static str,
    authority: StoreAuthority,
    payload_count: u64,
    payload_bytes: u64,
    files: Vec<StoreFile>,
}

#[derive(Serialize)]
struct WarmupReceipt<'a> {
    schema: &'static str,
    command: &'a [String],
    store: String,
    route_split: u8,
    persistent_enable_unset: bool,
    store_manifest_sha256: String,
    payload_count: u64,
    payload_bytes: u64,
}

pub(crate) fn run_trusted_route_capture(
    evidence_dir: &Path,
    jit_share: f64,
    workload: &[String],
) -> Result<()> {
    let executable = std::env::current_exe().context("resolve current carrick executable")?;
    capture_with_ops(
        &executable,
        evidence_dir,
        jit_share,
        workload,
        &mut SystemCaptureOps,
    )
}

fn capture_with_ops(
    executable: &Path,
    evidence_dir: &Path,
    jit_share: f64,
    workload: &[String],
    ops: &mut dyn CaptureOps,
) -> Result<()> {
    validate_jit_share(jit_share)?;
    if workload.first().map(String::as_str) != Some("run") {
        bail!("trusted-route capture workload must begin with the `run` subcommand");
    }
    fs::create_dir_all(evidence_dir)
        .with_context(|| format!("create evidence directory {}", evidence_dir.display()))?;
    let store = evidence_dir.join("store");
    require_empty_store(&store)?;
    fs::create_dir_all(&store)
        .with_context(|| format!("create isolated store {}", store.display()))?;

    let trace_path = evidence_dir.join("trace.raw");
    let capture_path = evidence_dir.join("capture.json");
    let snapshots = evidence_dir.join("snapshots");
    let census_path = evidence_dir.join("census.json");
    let pre_manifest_path = evidence_dir.join("store-pre.json");
    let post_manifest_path = evidence_dir.join("store-post.json");
    let warmup_path = evidence_dir.join("warmup.json");
    for reserved in [
        &trace_path,
        &capture_path,
        &snapshots,
        &census_path,
        &pre_manifest_path,
        &post_manifest_path,
        &warmup_path,
    ] {
        if reserved.exists() {
            bail!(
                "trusted-route evidence output already exists: {}",
                reserved.display()
            );
        }
    }

    let warmup = CaptureCommandSpec {
        phase: CapturePhase::Warmup,
        args: workload.to_vec(),
        environment: capture_environment(&store, None),
    };
    require_success(ops.run_command(executable, &warmup)?, CapturePhase::Warmup)?;
    let pre_manifest = store_manifest(&store).context("census store after warmup")?;
    require_payloads(&pre_manifest, "warmup")?;
    write_json_atomic(&pre_manifest_path, &pre_manifest)?;
    let pre_manifest_bytes = serde_json::to_vec(&pre_manifest).context("serialize pre-manifest")?;
    write_json_atomic(
        &warmup_path,
        &WarmupReceipt {
            schema: "carrick.trusted-route-warmup.v1",
            command: workload,
            store: store.to_string_lossy().into_owned(),
            route_split: 1,
            persistent_enable_unset: true,
            store_manifest_sha256: format!("{:x}", Sha256::digest(&pre_manifest_bytes)),
            payload_count: pre_manifest.payload_count,
            payload_bytes: pre_manifest.payload_bytes,
        },
    )?;

    fs::create_dir(&snapshots)
        .with_context(|| format!("create snapshot directory {}", snapshots.display()))?;
    let mut trace_args = vec![
        "trace".to_owned(),
        "--profile".to_owned(),
        "trusted-route".to_owned(),
        "--trace-out".to_owned(),
        trace_path.to_string_lossy().into_owned(),
        "--summary-jsonl".to_owned(),
        capture_path.to_string_lossy().into_owned(),
        "--".to_owned(),
    ];
    trace_args.extend_from_slice(workload);
    let trace = CaptureCommandSpec {
        phase: CapturePhase::Trace,
        args: trace_args,
        environment: capture_environment(&store, Some(&snapshots)),
    };
    require_success(ops.run_command(executable, &trace)?, CapturePhase::Trace)?;
    let post_manifest = store_manifest(&store).context("census store after traced workload")?;
    require_payloads(&post_manifest, "trace")?;
    if post_manifest.authority != pre_manifest.authority {
        bail!("isolated store authority identity changed between warmup and trace");
    }
    write_json_atomic(&post_manifest_path, &post_manifest)?;

    ops.run_census(&CensusRequest {
        trace: trace_path,
        capture: capture_path,
        snapshots,
        jit_share,
        output: census_path,
    })
}

fn require_empty_store(store: &Path) -> Result<()> {
    if !store.exists() {
        return Ok(());
    }
    if !store.is_dir() {
        bail!(
            "isolated store path is not a directory: {}",
            store.display()
        );
    }
    if fs::read_dir(store)
        .with_context(|| format!("read isolated store {}", store.display()))?
        .next()
        .transpose()?
        .is_some()
    {
        bail!(
            "isolated trusted-route store is not empty: {}",
            store.display()
        );
    }
    Ok(())
}

fn require_success(status: CaptureExit, phase: CapturePhase) -> Result<()> {
    if !status.success {
        bail!(
            "trusted-route {} command failed with status {:?}",
            match phase {
                CapturePhase::Warmup => "warmup",
                CapturePhase::Trace => "trace",
            },
            status.code
        );
    }
    Ok(())
}

fn require_payloads(manifest: &StoreManifest, phase: &str) -> Result<()> {
    if manifest.payload_count == 0 || manifest.payload_bytes == 0 {
        bail!("trusted-route {phase} produced zero complete store payloads");
    }
    Ok(())
}

fn store_manifest(store: &Path) -> Result<StoreManifest> {
    let mut paths = Vec::new();
    collect_store_files(store, store, &mut paths)?;
    paths.sort();
    let mut files = Vec::with_capacity(paths.len());
    let mut code_stems = BTreeSet::new();
    let mut metadata_stems = BTreeSet::new();
    let mut payload_bytes = 0_u64;
    for path in paths {
        let relative = path
            .strip_prefix(store)
            .context("store file escaped its root")?;
        let relative = relative
            .to_str()
            .ok_or_else(|| anyhow!("store file has a non-UTF-8 path"))?
            .to_owned();
        let metadata = fs::symlink_metadata(&path)
            .with_context(|| format!("stat store file {}", path.display()))?;
        let bytes =
            fs::read(&path).with_context(|| format!("read store file {}", path.display()))?;
        if let Some(stem) = relative.strip_suffix(".code") {
            if bytes.is_empty() {
                bail!("store code payload {relative:?} is empty");
            }
            code_stems.insert(stem.to_owned());
            payload_bytes = payload_bytes
                .checked_add(metadata.len())
                .ok_or_else(|| anyhow!("store payload byte count overflow"))?;
        } else if let Some(stem) = relative.strip_suffix(".metadata-v5") {
            if bytes.is_empty() {
                bail!("store metadata payload {relative:?} is empty");
            }
            metadata_stems.insert(stem.to_owned());
            payload_bytes = payload_bytes
                .checked_add(metadata.len())
                .ok_or_else(|| anyhow!("store payload byte count overflow"))?;
        }
        files.push(StoreFile {
            path: relative,
            bytes: metadata.len(),
            device: metadata.dev(),
            inode: metadata.ino(),
            sha256: format!("{:x}", Sha256::digest(&bytes)),
        });
    }
    if code_stems != metadata_stems {
        bail!("isolated store has an incomplete code/metadata payload pair");
    }
    let authority_path = store.join(".carrick-authority");
    let authority_metadata = fs::symlink_metadata(&authority_path)
        .with_context(|| format!("stat store authority {}", authority_path.display()))?;
    if !authority_metadata.file_type().is_file() {
        bail!("store authority marker is not a regular file");
    }
    let authority_bytes = fs::read(&authority_path)
        .with_context(|| format!("read store authority {}", authority_path.display()))?;
    if authority_bytes.len() != 16 {
        bail!("store authority marker is malformed");
    }
    Ok(StoreManifest {
        schema: "carrick.trusted-route-store-manifest.v1",
        authority: StoreAuthority {
            device: authority_metadata.dev(),
            inode: authority_metadata.ino(),
            sha256: format!("{:x}", Sha256::digest(&authority_bytes)),
        },
        payload_count: u64::try_from(code_stems.len())
            .context("store payload count exceeds u64")?,
        payload_bytes,
        files,
    })
}

fn collect_store_files(root: &Path, directory: &Path, paths: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(directory)
        .with_context(|| format!("read store directory {}", directory.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            bail!(
                "isolated store contains a symbolic link: {}",
                path.display()
            );
        }
        if file_type.is_dir() {
            collect_store_files(root, &path, paths)?;
        } else if file_type.is_file() {
            path.strip_prefix(root).context("store path escaped root")?;
            paths.push(path);
        } else {
            bail!(
                "isolated store contains a non-file entry: {}",
                path.display()
            );
        }
    }
    Ok(())
}

fn write_json_atomic<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(value).context("serialize trusted-route evidence")?;
    bytes.push(b'\n');
    write_atomic(path, &bytes)
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
                "origin": if pid == 43 { "unit-replay" } else { "owned" },
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

    fn write_snapshot_named(directory: &Path, name: &str, pid: u32, base: u64) {
        let code = bytes(&words());
        fs::write(directory.join(format!("{name}.bin")), &code).expect("snapshot code");
        fs::write(
            directory.join(format!("{name}.json")),
            serde_json::to_vec(&snapshot_value(pid, base, &code)).expect("snapshot JSON"),
        )
        .expect("snapshot index");
    }

    fn write_snapshot(directory: &Path, pid: u32, base: u64) {
        write_snapshot_named(directory, &pid.to_string(), pid, base);
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
        assert_eq!(
            report.route_origins,
            OriginTallies {
                owned: 1,
                unit_replay: 1,
            }
        );
        assert_eq!(
            report.route_samples_by_origin,
            OriginTallies {
                owned: 60,
                unit_replay: 18,
            }
        );
        assert!(report.validation_failures.is_empty());
    }

    #[test]
    fn trusted_route_census_accepts_nonoverlapping_exec_snapshots_for_one_pid() {
        let fixture = make_fixture(&[(42, 0x1000, 3), (42, 0x3000, 5)]);
        write_snapshot_named(&fixture.snapshots, "42-exec-2", 42, 0x3000);

        let report =
            build_trusted_route_census(&fixture.trace, &fixture.capture, &fixture.snapshots, 0.45)
                .expect("non-overlapping snapshots for one PID");

        assert_eq!(report.matched_samples, 8);
        assert_eq!(report.missing_pid_samples, 0);
        assert_eq!(report.missing_range_samples, 0);
        assert_eq!(report.routes.fallthrough, 8);
        assert_eq!(report.block_count, 3);
        assert!(report.validation_failures.is_empty());
    }

    #[test]
    fn trusted_route_census_rejects_overlapping_exec_snapshots_for_one_pid() {
        let fixture = make_fixture(&valid_rows());
        write_snapshot_named(&fixture.snapshots, "42-overlap", 42, 0x1020);

        assert!(
            build_trusted_route_census(&fixture.trace, &fixture.capture, &fixture.snapshots, 0.45,)
                .is_err()
        );
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

    #[derive(Clone, Copy)]
    enum FakeCaptureMode {
        Success,
        WarmupFailure,
        TraceFailure,
        NoWarmupPayload,
        RemoveTracePayload,
        ReplaceAuthority,
    }

    struct FakeCaptureOps {
        mode: FakeCaptureMode,
        events: Vec<&'static str>,
        specs: Vec<CaptureCommandSpec>,
        census_requests: Vec<CensusRequest>,
    }

    impl FakeCaptureOps {
        fn new(mode: FakeCaptureMode) -> Self {
            Self {
                mode,
                events: Vec::new(),
                specs: Vec::new(),
                census_requests: Vec::new(),
            }
        }

        fn store(spec: &CaptureCommandSpec) -> PathBuf {
            spec.environment
                .set
                .get("CARRICK_DSR_STORE_DIR")
                .map(PathBuf::from)
                .expect("capture store environment")
        }

        fn write_warmup_store(&self, store: &Path) {
            fs::write(store.join(".carrick-authority"), [7_u8; 16]).expect("authority");
            if !matches!(self.mode, FakeCaptureMode::NoWarmupPayload) {
                fs::write(store.join("unit.code"), [1_u8, 2, 3, 4]).expect("code payload");
                fs::write(store.join("unit.metadata-v5"), b"metadata").expect("metadata payload");
            }
        }
    }

    impl CaptureOps for FakeCaptureOps {
        fn run_command(
            &mut self,
            _executable: &Path,
            spec: &CaptureCommandSpec,
        ) -> Result<CaptureExit> {
            self.specs.push(spec.clone());
            let store = Self::store(spec);
            match spec.phase {
                CapturePhase::Warmup => {
                    self.events.push("warmup");
                    if matches!(self.mode, FakeCaptureMode::WarmupFailure) {
                        return Ok(CaptureExit {
                            success: false,
                            code: Some(17),
                        });
                    }
                    self.write_warmup_store(&store);
                }
                CapturePhase::Trace => {
                    self.events.push("trace");
                    if matches!(self.mode, FakeCaptureMode::TraceFailure) {
                        return Ok(CaptureExit {
                            success: false,
                            code: Some(19),
                        });
                    }
                    if matches!(self.mode, FakeCaptureMode::RemoveTracePayload) {
                        fs::remove_file(store.join("unit.code")).expect("remove code payload");
                        fs::remove_file(store.join("unit.metadata-v5"))
                            .expect("remove metadata payload");
                    }
                    if matches!(self.mode, FakeCaptureMode::ReplaceAuthority) {
                        fs::rename(
                            store.join(".carrick-authority"),
                            store.join(".old-authority"),
                        )
                        .expect("retire authority inode");
                        fs::write(store.join(".carrick-authority"), [9_u8; 16])
                            .expect("replacement authority");
                    }
                }
            }
            Ok(CaptureExit {
                success: true,
                code: Some(0),
            })
        }

        fn run_census(&mut self, request: &CensusRequest) -> Result<()> {
            self.events.push("census");
            self.census_requests.push(request.clone());
            Ok(())
        }
    }

    fn run_fake_capture(evidence: &Path, mode: FakeCaptureMode) -> (Result<()>, FakeCaptureOps) {
        let mut ops = FakeCaptureOps::new(mode);
        let result = capture_with_ops(
            Path::new("/tmp/fake-carrick"),
            evidence,
            0.46505,
            &[
                "run".to_owned(),
                "--exec-backend".to_owned(),
                "native".to_owned(),
                "fixture".to_owned(),
            ],
            &mut ops,
        );
        (result, ops)
    }

    #[test]
    fn trusted_route_capture_orders_isolated_warmup_trace_and_census() {
        let temp = tempfile::tempdir().expect("capture root");
        let evidence = temp.path().join("evidence");

        let (result, ops) = run_fake_capture(&evidence, FakeCaptureMode::Success);

        result.expect("successful capture protocol");
        assert_eq!(ops.events, ["warmup", "trace", "census"]);
        assert_eq!(ops.specs.len(), 2);
        let warmup = &ops.specs[0];
        let trace = &ops.specs[1];
        assert_eq!(warmup.phase, CapturePhase::Warmup);
        assert_eq!(warmup.args[0], "run");
        assert!(!warmup.args.iter().any(|arg| arg == "trusted-route"));
        assert_eq!(trace.phase, CapturePhase::Trace);
        assert_eq!(&trace.args[..3], ["trace", "--profile", "trusted-route"]);
        for spec in [warmup, trace] {
            assert!(
                spec.environment
                    .remove
                    .contains(&"CARRICK_DSR_PERSISTENT_STORE")
            );
            assert!(
                !spec
                    .environment
                    .set
                    .contains_key("CARRICK_DSR_PERSISTENT_STORE")
            );
            assert_eq!(
                spec.environment
                    .set
                    .get("CARRICK_DSR_TRUSTED_ROUTE_SPLIT")
                    .map(OsString::as_os_str),
                Some(std::ffi::OsStr::new("1"))
            );
            assert_eq!(
                spec.environment
                    .set
                    .get("CARRICK_DSR_STORE_DIR")
                    .map(PathBuf::from),
                Some(evidence.join("store"))
            );
        }
        assert!(
            !warmup
                .environment
                .set
                .contains_key("CARRICK_DSR_CODE_SNAPSHOT_DIR")
        );
        assert_eq!(
            trace
                .environment
                .set
                .get("CARRICK_DSR_CODE_SNAPSHOT_DIR")
                .map(PathBuf::from),
            Some(evidence.join("snapshots"))
        );
        assert_eq!(ops.census_requests.len(), 1);
        let census = &ops.census_requests[0];
        assert_eq!(census.trace, evidence.join("trace.raw"));
        assert_eq!(census.capture, evidence.join("capture.json"));
        assert_eq!(census.snapshots, evidence.join("snapshots"));
        assert_eq!(census.output, evidence.join("census.json"));
        assert!(evidence.join("warmup.json").is_file());
        assert!(evidence.join("store-pre.json").is_file());
        assert!(evidence.join("store-post.json").is_file());
    }

    #[test]
    fn trusted_route_capture_refuses_a_nonempty_store_before_running() {
        let temp = tempfile::tempdir().expect("capture root");
        let evidence = temp.path().join("evidence");
        fs::create_dir_all(evidence.join("store")).expect("store");
        fs::write(evidence.join("store/existing"), b"do not touch").expect("existing store");

        let (result, ops) = run_fake_capture(&evidence, FakeCaptureMode::Success);

        assert!(result.is_err());
        assert!(ops.events.is_empty());
        assert!(evidence.join("store/existing").is_file());
    }

    #[test]
    fn trusted_route_capture_rejects_failed_phases_and_zero_payloads_before_census() {
        for mode in [
            FakeCaptureMode::WarmupFailure,
            FakeCaptureMode::TraceFailure,
            FakeCaptureMode::NoWarmupPayload,
            FakeCaptureMode::RemoveTracePayload,
        ] {
            let temp = tempfile::tempdir().expect("capture root");
            let (result, ops) = run_fake_capture(&temp.path().join("evidence"), mode);
            assert!(result.is_err());
            assert!(!ops.events.contains(&"census"));
        }
    }

    #[test]
    fn trusted_route_capture_rejects_authority_inode_change_before_census() {
        let temp = tempfile::tempdir().expect("capture root");

        let (result, ops) = run_fake_capture(
            &temp.path().join("evidence"),
            FakeCaptureMode::ReplaceAuthority,
        );

        assert!(result.is_err());
        assert_eq!(ops.events, ["warmup", "trace"]);
        assert!(ops.census_requests.is_empty());
    }

    #[test]
    fn trusted_route_capture_removes_persistent_enable_from_both_phases() {
        let environment = capture_environment(Path::new("/tmp/store"), None);
        assert!(environment.remove.contains(&"CARRICK_DSR_PERSISTENT_STORE"));
        assert_eq!(
            environment
                .set
                .get("CARRICK_DSR_TRUSTED_ROUTE_SPLIT")
                .map(OsString::as_os_str),
            Some(std::ffi::OsStr::new("1"))
        );
        assert!(
            !environment
                .set
                .contains_key("CARRICK_DSR_CODE_SNAPSHOT_DIR")
        );

        let traced = capture_environment(Path::new("/tmp/store"), Some(Path::new("/tmp/snaps")));
        assert_eq!(
            traced
                .set
                .get("CARRICK_DSR_CODE_SNAPSHOT_DIR")
                .map(OsString::as_os_str),
            Some(std::ffi::OsStr::new("/tmp/snaps"))
        );
    }
}
