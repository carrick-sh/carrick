//! Fail-closed offline join for sampled native-DSR JIT PCs.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct PcSample {
    pid: u32,
    pc: u64,
    count: u64,
}

#[derive(Debug)]
struct TraceData {
    samples: u64,
    jit_samples: u64,
    non_jit_samples: u64,
    pc_samples: Vec<PcSample>,
    parents: BTreeMap<u32, u32>,
}

fn parse_trace(mut input: impl Read) -> anyhow::Result<TraceData> {
    let mut text = String::new();
    input
        .read_to_string(&mut text)
        .context("read SHAPE1 trace as UTF-8")?;
    let mut samples = None;
    let mut copyin_errors = None;
    let mut jit_samples = None;
    let mut non_jit_samples = None;
    let mut completion = 0_u8;
    let mut pc_samples = Vec::new();
    let mut pc_keys = BTreeSet::new();
    let mut parents = BTreeMap::new();

    for (index, raw) in text.lines().enumerate() {
        let line_number = index + 1;
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix("PC ") {
            let fields = rest.split_ascii_whitespace().collect::<Vec<_>>();
            if fields.len() != 3 {
                bail!("line {line_number}: malformed PC row `{line}`");
            }
            let pid = fields[0]
                .parse::<u32>()
                .with_context(|| format!("line {line_number}: invalid PC pid"))?;
            let pc = u64::from_str_radix(
                fields[1]
                    .strip_prefix("0x")
                    .ok_or_else(|| anyhow::anyhow!("line {line_number}: PC is not hex"))?,
                16,
            )
            .with_context(|| format!("line {line_number}: invalid PC address"))?;
            let count = fields[2]
                .parse::<u64>()
                .with_context(|| format!("line {line_number}: invalid PC count"))?;
            if count == 0 {
                bail!("line {line_number}: zero PC count");
            }
            if !pc_keys.insert((pid, pc)) {
                bail!("line {line_number}: duplicate PC row for pid {pid} pc {pc:#x}");
            }
            pc_samples.push(PcSample { pid, pc, count });
            continue;
        }
        let Some(protocol) = line.strip_prefix("SHAPE1|") else {
            continue;
        };
        if matches!(protocol, "section=totals" | "section=region" | "section=pc") {
            continue;
        }
        if let Some(rest) = protocol.strip_prefix("fork|") {
            let fields = rest.split('|').collect::<Vec<_>>();
            if fields.len() != 2 {
                bail!("line {line_number}: malformed fork row");
            }
            let parent = parse_u32_field(fields[0], "parent=", line_number)?;
            let child = parse_u32_field(fields[1], "child=", line_number)?;
            if parent == child {
                bail!("line {line_number}: process cannot parent itself");
            }
            if parents.insert(child, parent).is_some() {
                bail!("line {line_number}: duplicate parent for child {child}");
            }
            continue;
        }
        if let Some(value) = protocol.strip_prefix("samples=") {
            set_once(
                &mut samples,
                parse_u64(value, "samples", line_number)?,
                "samples",
                line_number,
            )?;
            continue;
        }
        if let Some(value) = protocol.strip_prefix("copyin-errors=") {
            set_once(
                &mut copyin_errors,
                parse_u64(value, "copyin-errors", line_number)?,
                "copyin-errors",
                line_number,
            )?;
            continue;
        }
        if let Some(rest) = protocol.strip_prefix("region=") {
            let Some((region, count)) = rest.split_once("|count=") else {
                bail!("line {line_number}: malformed region row");
            };
            let count = parse_u64(count, "region count", line_number)?;
            match region {
                "jit" => set_once(&mut jit_samples, count, "jit region", line_number)?,
                "non-jit" => set_once(&mut non_jit_samples, count, "non-jit region", line_number)?,
                _ => bail!("line {line_number}: unknown region `{region}`"),
            }
            continue;
        }
        if protocol.starts_with("complete|") {
            completion = completion
                .checked_add(1)
                .context("completion record count overflow")?;
            if protocol != "complete|bounded=0|target_completed=1|target_exit_reason=1" {
                bail!("line {line_number}: trace did not complete naturally: `{line}`");
            }
            continue;
        }
        bail!("line {line_number}: unknown SHAPE1 record `{line}`");
    }

    if completion != 1 {
        bail!("expected exactly one completion record, found {completion}");
    }
    let samples = samples.context("missing SHAPE1 samples total")?;
    let copyin_errors = copyin_errors.context("missing SHAPE1 copyin-errors")?;
    if copyin_errors != 0 {
        bail!("trace recorded {copyin_errors} copyin errors");
    }
    let jit_samples = jit_samples.context("missing JIT region count")?;
    let non_jit_samples = non_jit_samples.context("missing non-JIT region count")?;
    let region_total = jit_samples
        .checked_add(non_jit_samples)
        .context("region sample total overflow")?;
    if samples != region_total {
        bail!("sample total {samples} does not equal region total {region_total}");
    }
    let pc_total = pc_samples.iter().try_fold(0_u64, |sum, row| {
        sum.checked_add(row.count)
            .context("PC sample total overflow")
    })?;
    if pc_total != jit_samples {
        bail!("PC sample total {pc_total} does not equal JIT region total {jit_samples}");
    }
    if jit_samples == 0 {
        bail!("trace contains zero JIT samples");
    }
    for &child in parents.keys() {
        let mut seen = BTreeSet::new();
        let mut cursor = child;
        while let Some(&parent) = parents.get(&cursor) {
            if !seen.insert(cursor) {
                bail!("fork ancestry cycle contains pid {cursor}");
            }
            cursor = parent;
        }
    }

    Ok(TraceData {
        samples,
        jit_samples,
        non_jit_samples,
        pc_samples,
        parents,
    })
}

fn parse_u32_field(field: &str, prefix: &str, line: usize) -> anyhow::Result<u32> {
    field
        .strip_prefix(prefix)
        .ok_or_else(|| anyhow::anyhow!("line {line}: expected `{prefix}` field"))?
        .parse::<u32>()
        .with_context(|| format!("line {line}: invalid `{prefix}` value"))
}

fn parse_u64(value: &str, name: &str, line: usize) -> anyhow::Result<u64> {
    value
        .parse::<u64>()
        .with_context(|| format!("line {line}: invalid {name}"))
}

fn set_once<T>(slot: &mut Option<T>, value: T, name: &str, line: usize) -> anyhow::Result<()> {
    if slot.replace(value).is_some() {
        bail!("line {line}: duplicate {name} record");
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SnapshotMetadata {
    schema: String,
    pid: u32,
    cache_base: u64,
    code_len: usize,
    code_sha256: String,
    blocks: Vec<(u64, u64)>,
}

#[derive(Debug)]
struct Snapshot {
    path: PathBuf,
    base: u64,
    code: Vec<u8>,
    blocks: Vec<(u64, u64)>,
}

impl Snapshot {
    fn contains(&self, pc: u64) -> bool {
        let Some(end) = self.base.checked_add(self.code.len() as u64) else {
            return false;
        };
        pc >= self.base && pc < end
    }

    fn word_at(&self, pc: u64) -> anyhow::Result<u32> {
        let offset = pc
            .checked_sub(self.base)
            .with_context(|| format!("PC {pc:#x} precedes snapshot base {:#x}", self.base))?;
        if offset % 4 != 0 {
            bail!(
                "PC {pc:#x} is not word-aligned in snapshot {}",
                self.path.display()
            );
        }
        let offset = usize::try_from(offset).context("snapshot offset does not fit usize")?;
        let end = offset
            .checked_add(4)
            .context("snapshot word offset overflow")?;
        let bytes = self
            .code
            .get(offset..end)
            .with_context(|| format!("PC {pc:#x} is truncated in {}", self.path.display()))?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }
}

#[derive(Debug)]
struct SnapshotSet {
    by_pid: BTreeMap<u32, Vec<Snapshot>>,
    manifest_sha256: String,
    count: usize,
    blocks: usize,
}

fn load_snapshots(dir: &Path) -> anyhow::Result<SnapshotSet> {
    let entries =
        fs::read_dir(dir).with_context(|| format!("read snapshot directory {}", dir.display()))?;
    let mut json_paths = BTreeMap::new();
    let mut bin_paths = BTreeMap::new();
    for entry in entries {
        let entry = entry.with_context(|| format!("read entry in {}", dir.display()))?;
        if !entry
            .file_type()
            .with_context(|| format!("read file type for {}", entry.path().display()))?
            .is_file()
        {
            continue;
        }
        let path = entry.path();
        let Some(extension) = path.extension().and_then(|value| value.to_str()) else {
            continue;
        };
        if !matches!(extension, "json" | "bin") {
            continue;
        }
        let stem = path
            .file_stem()
            .and_then(|value| value.to_str())
            .with_context(|| format!("non-UTF-8 snapshot name {}", path.display()))?
            .to_owned();
        let target = if extension == "json" {
            &mut json_paths
        } else {
            &mut bin_paths
        };
        if target.insert(stem.clone(), path.clone()).is_some() {
            bail!("duplicate snapshot `{stem}.{extension}`");
        }
    }
    if json_paths.is_empty() && bin_paths.is_empty() {
        bail!("snapshot directory {} contains no snapshots", dir.display());
    }
    let json_stems = json_paths.keys().cloned().collect::<BTreeSet<_>>();
    let bin_stems = bin_paths.keys().cloned().collect::<BTreeSet<_>>();
    if json_stems != bin_stems {
        let missing_bins = json_stems.difference(&bin_stems).collect::<Vec<_>>();
        let missing_json = bin_stems.difference(&json_stems).collect::<Vec<_>>();
        bail!(
            "snapshot pairs are incomplete: missing .bin for {missing_bins:?}; missing .json for {missing_json:?}"
        );
    }

    let mut by_pid: BTreeMap<u32, Vec<Snapshot>> = BTreeMap::new();
    let mut manifest = Sha256::new();
    for (stem, json_path) in json_paths {
        let bin_path = bin_paths
            .get(&stem)
            .with_context(|| format!("snapshot {stem} lost its paired payload"))?;
        let json = fs::read(&json_path)
            .with_context(|| format!("read snapshot metadata {}", json_path.display()))?;
        let metadata: SnapshotMetadata = serde_json::from_slice(&json)
            .with_context(|| format!("parse snapshot metadata {}", json_path.display()))?;
        if metadata.schema != "carrick.code-snapshot.v4" {
            bail!(
                "snapshot {} has unsupported schema `{}`",
                json_path.display(),
                metadata.schema
            );
        }
        let code = fs::read(bin_path)
            .with_context(|| format!("read snapshot payload {}", bin_path.display()))?;
        if code.len() != metadata.code_len {
            bail!(
                "snapshot {} length {} does not match authenticated length {}",
                bin_path.display(),
                code.len(),
                metadata.code_len
            );
        }
        if code.len() % 4 != 0 {
            bail!("snapshot {} length is not word-aligned", bin_path.display());
        }
        metadata
            .cache_base
            .checked_add(code.len() as u64)
            .with_context(|| format!("snapshot {} address range overflows", bin_path.display()))?;
        let code_sha256 = format!("{:x}", Sha256::digest(&code));
        if code_sha256 != metadata.code_sha256 {
            bail!(
                "snapshot {} SHA-256 {} does not match authenticated digest {}",
                bin_path.display(),
                code_sha256,
                metadata.code_sha256
            );
        }
        let json_sha256 = format!("{:x}", Sha256::digest(&json));
        manifest.update(stem.as_bytes());
        manifest.update([0]);
        manifest.update(json_sha256.as_bytes());
        manifest.update([0]);
        manifest.update(code_sha256.as_bytes());
        manifest.update(b"\n");
        by_pid.entry(metadata.pid).or_default().push(Snapshot {
            path: bin_path.clone(),
            base: metadata.cache_base,
            code,
            blocks: metadata.blocks,
        });
    }
    for snapshots in by_pid.values_mut() {
        snapshots.sort_by(|left, right| left.path.cmp(&right.path));
    }
    let count = by_pid.values().map(Vec::len).sum();
    let blocks = by_pid
        .values()
        .flatten()
        .map(|snapshot| snapshot.blocks.len())
        .sum();
    Ok(SnapshotSet {
        by_pid,
        manifest_sha256: format!("{:x}", manifest.finalize()),
        count,
        blocks,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ResolvedWord {
    word: u32,
    inherited: bool,
}

fn resolve_sample(
    sample: PcSample,
    snapshots: &SnapshotSet,
    parents: &BTreeMap<u32, u32>,
) -> anyhow::Result<ResolvedWord> {
    let own = snapshots.by_pid.get(&sample.pid).with_context(|| {
        format!(
            "pid {} has samples but no authenticated snapshot",
            sample.pid
        )
    })?;
    let own_matches = own
        .iter()
        .filter(|snapshot| snapshot.contains(sample.pc))
        .collect::<Vec<_>>();
    match own_matches.as_slice() {
        [snapshot] => {
            return Ok(ResolvedWord {
                word: snapshot.word_at(sample.pc)?,
                inherited: false,
            });
        }
        [] => {}
        matches => {
            bail!(
                "pid {} PC {:#x} resolves in {} own snapshots",
                sample.pid,
                sample.pc,
                matches.len()
            );
        }
    }

    let mut candidates = Vec::new();
    let mut cursor = sample.pid;
    let mut seen = BTreeSet::new();
    while let Some(&parent) = parents.get(&cursor) {
        if !seen.insert(cursor) {
            bail!("fork ancestry cycle while resolving pid {}", sample.pid);
        }
        if let Some(parent_snapshots) = snapshots.by_pid.get(&parent) {
            candidates.extend(
                parent_snapshots
                    .iter()
                    .filter(|snapshot| snapshot.contains(sample.pc)),
            );
        }
        cursor = parent;
    }
    match candidates.as_slice() {
        [snapshot] => Ok(ResolvedWord {
            word: snapshot.word_at(sample.pc)?,
            inherited: true,
        }),
        [] => bail!(
            "pid {} PC {:#x} resolves in no own or ancestor snapshot",
            sample.pid,
            sample.pc
        ),
        matches => bail!(
            "pid {} PC {:#x} resolves ambiguously in {} ancestor snapshots",
            sample.pid,
            sample.pc,
            matches.len()
        ),
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum Direction {
    Load,
    Store,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ContextAccess {
    direction: Direction,
    slot: u32,
    register: u8,
}

fn decode_context64(word: u32) -> Option<ContextAccess> {
    let direction = match word & 0xffc0_03e0 {
        0xf940_0380 => Direction::Load,
        0xf900_0380 => Direction::Store,
        _ => return None,
    };
    Some(ContextAccess {
        direction,
        slot: ((word >> 10) & 0xfff) * 8,
        register: (word & 0x1f) as u8,
    })
}

#[derive(Debug, Serialize)]
struct JitShapeReport {
    schema: &'static str,
    inputs: InputsSection,
    trace: TraceSection,
    snapshots: SnapshotSection,
    coverage: CoverageSection,
    instruction_families: Vec<SampleRow>,
    context_rows: Vec<ContextRow>,
}

#[derive(Debug, Serialize)]
struct InputsSection {
    trace_sha256: String,
    snapshot_manifest_sha256: String,
    jit_share_of_total_cpu: f64,
}

#[derive(Debug, Serialize)]
struct TraceSection {
    samples: u64,
    jit_samples: u64,
    non_jit_samples: u64,
    pc_rows: usize,
    fork_links: usize,
}

#[derive(Debug, Serialize)]
struct SnapshotSection {
    files: usize,
    pids: usize,
    indexed_blocks: usize,
}

#[derive(Debug, Serialize)]
struct CoverageSection {
    matched_jit_samples: u64,
    own_samples: u64,
    inherited_samples: u64,
    missing_samples: u64,
}

#[derive(Debug, Serialize)]
struct SampleRow {
    family: &'static str,
    samples: u64,
    share_of_matched_jit: f64,
    projected_share_of_total_cpu: f64,
}

#[derive(Debug, Serialize)]
struct ContextRow {
    key: String,
    direction: &'static str,
    slot: u32,
    physical_register: u8,
    semantic_label: &'static str,
    samples: u64,
    share_of_matched_jit: f64,
    projected_share_of_total_cpu: f64,
}

pub(crate) fn run_jit_shape_census(
    trace_path: &Path,
    snapshot_dir: &Path,
    jit_share_of_total_cpu: f64,
) -> anyhow::Result<()> {
    let trace = fs::read(trace_path)
        .with_context(|| format!("read shape trace {}", trace_path.display()))?;
    let report = build_report(&trace, snapshot_dir, jit_share_of_total_cpu)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

fn build_report(
    trace_bytes: &[u8],
    snapshot_dir: &Path,
    jit_share_of_total_cpu: f64,
) -> anyhow::Result<JitShapeReport> {
    if !jit_share_of_total_cpu.is_finite()
        || jit_share_of_total_cpu <= 0.0
        || jit_share_of_total_cpu > 1.0
    {
        bail!("--jit-share-of-total must be finite and in the interval (0, 1]");
    }
    let trace = parse_trace(trace_bytes)?;
    let snapshots = load_snapshots(snapshot_dir)?;
    let mut own_samples = 0_u64;
    let mut inherited_samples = 0_u64;
    let mut families: BTreeMap<&'static str, u64> = BTreeMap::new();
    let mut context: BTreeMap<(Direction, u32, u8), u64> = BTreeMap::new();

    for sample in &trace.pc_samples {
        let resolved = resolve_sample(*sample, &snapshots, &trace.parents)?;
        let coverage = if resolved.inherited {
            &mut inherited_samples
        } else {
            &mut own_samples
        };
        checked_increment(coverage, sample.count, "coverage sample count")?;
        checked_increment(
            families.entry(classify_family(resolved.word)).or_default(),
            sample.count,
            "instruction-family sample count",
        )?;
        if let Some(access) = decode_context64(resolved.word) {
            checked_increment(
                context
                    .entry((access.direction, access.slot, access.register))
                    .or_default(),
                sample.count,
                "context-row sample count",
            )?;
        }
    }
    let matched_jit_samples = own_samples
        .checked_add(inherited_samples)
        .context("matched sample count overflow")?;
    if matched_jit_samples != trace.jit_samples {
        bail!(
            "resolved sample count {matched_jit_samples} does not equal JIT trace count {}",
            trace.jit_samples
        );
    }
    let family_total = families.values().try_fold(0_u64, |total, count| {
        total.checked_add(*count).context("family total overflow")
    })?;
    if family_total != matched_jit_samples {
        bail!("instruction-family total does not equal matched JIT samples");
    }

    let instruction_families = families
        .into_iter()
        .map(|(family, samples)| {
            let share = samples as f64 / matched_jit_samples as f64;
            SampleRow {
                family,
                samples,
                share_of_matched_jit: share,
                projected_share_of_total_cpu: share * jit_share_of_total_cpu,
            }
        })
        .collect();
    let context_rows = context
        .into_iter()
        .map(|((direction, slot, physical_register), samples)| {
            let share = samples as f64 / matched_jit_samples as f64;
            ContextRow {
                key: format!("{}:slot={slot}:x{physical_register}", direction.as_str()),
                direction: direction.as_str(),
                slot,
                physical_register,
                semantic_label: context_semantic_label(slot),
                samples,
                share_of_matched_jit: share,
                projected_share_of_total_cpu: share * jit_share_of_total_cpu,
            }
        })
        .collect();

    Ok(JitShapeReport {
        schema: "carrick.jit-shape-census.v1",
        inputs: InputsSection {
            trace_sha256: format!("{:x}", Sha256::digest(trace_bytes)),
            snapshot_manifest_sha256: snapshots.manifest_sha256,
            jit_share_of_total_cpu,
        },
        trace: TraceSection {
            samples: trace.samples,
            jit_samples: trace.jit_samples,
            non_jit_samples: trace.non_jit_samples,
            pc_rows: trace.pc_samples.len(),
            fork_links: trace.parents.len(),
        },
        snapshots: SnapshotSection {
            files: snapshots.count,
            pids: snapshots.by_pid.len(),
            indexed_blocks: snapshots.blocks,
        },
        coverage: CoverageSection {
            matched_jit_samples,
            own_samples,
            inherited_samples,
            missing_samples: 0,
        },
        instruction_families,
        context_rows,
    })
}

fn checked_increment(total: &mut u64, count: u64, name: &str) -> anyhow::Result<()> {
    *total = total
        .checked_add(count)
        .with_context(|| format!("{name} overflow"))?;
    Ok(())
}

impl Direction {
    fn as_str(self) -> &'static str {
        match self {
            Self::Load => "load",
            Self::Store => "store",
        }
    }
}

fn classify_family(word: u32) -> &'static str {
    if (word & 0xffc0_03e0) == 0xf900_0380 {
        "ctx-store64"
    } else if (word & 0xffc0_03e0) == 0xf940_0380 {
        "ctx-load64"
    } else if (word & 0xffc0_03e0) == 0xb900_0380 {
        "ctx-store32"
    } else if (word & 0xffc0_03e0) == 0xb940_0380 {
        "ctx-load32"
    } else if matches!(word & 0xffc0_03e0, 0xa900_0380 | 0xa940_0380) {
        "ctx-pair"
    } else if (word & 0xffff_fc00) == 0xc8df_fc00 {
        "guard-ldar"
    } else if (word & 0xffc0_001f) == 0xd340_0012 {
        "window-ubfm-x18"
    } else if (word & 0xff00_001f) == 0xb400_0012 {
        "window-cbz-x18"
    } else if matches!(word & 0xffff_fc00, 0xb257_0000 | 0xb251_0000) {
        "bias-orr"
    } else if (word & 0xffff_ffe0) == 0xd51b_4200 {
        "nzcv-msr"
    } else if (word & 0xffff_ffe0) == 0xd53b_4200 {
        "nzcv-mrs"
    } else if matches!(
        word & 0xff80_001f,
        0x5280_0011 | 0x7280_0011 | 0xd280_0011 | 0xf280_0011
    ) {
        "x17-materialize"
    } else if matches!(
        word & 0xff80_001f,
        0x5280_0012 | 0x7280_0012 | 0xd280_0012 | 0xf280_0012
    ) {
        "x18-materialize"
    } else if word == 0xd61f_0220 {
        "br-x17"
    } else {
        "guest-other"
    }
}

fn context_semantic_label(slot: u32) -> &'static str {
    match slot {
        936 => "nzcv-recovery",
        1072 => "entry",
        1080 => "exit-target",
        1120 => "rewrite-scratch",
        1128 => "rewrite-context-scratch-and-guest-x17",
        1144 => "generation",
        1160 => "indirect-x15-scratch",
        1168 => "indirect-x30-scratch",
        1192 => "host-bias",
        1200 => "guest-fault-address",
        1272 => "indirect-cache-pointer",
        144 => "guest-virtual-x18",
        152 => "guest-virtual-x19",
        224 => "guest-virtual-x28",
        _ => "unclassified",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD_TRACE: &str = "\
SHAPE1|fork|parent=10|child=11
SHAPE1|section=totals
SHAPE1|samples=9
SHAPE1|copyin-errors=0
SHAPE1|section=region
SHAPE1|region=jit|count=7
SHAPE1|region=non-jit|count=2
SHAPE1|section=pc
PC 10 0x1000 3
PC 11 0x2000 4
SHAPE1|complete|bounded=0|target_completed=1|target_exit_reason=1
";

    #[test]
    fn trace_parser_accepts_complete_consistent_input() {
        let trace = parse_trace(GOOD_TRACE.as_bytes()).expect("valid trace");
        assert_eq!(trace.samples, 9);
        assert_eq!(trace.jit_samples, 7);
        assert_eq!(trace.pc_samples.len(), 2);
        assert_eq!(trace.parents.get(&11), Some(&10));
    }

    #[test]
    fn trace_parser_rejects_incomplete_or_inconsistent_input() {
        let mutations = [
            GOOD_TRACE.replace(
                "SHAPE1|complete|bounded=0|target_completed=1|target_exit_reason=1\n",
                "",
            ),
            GOOD_TRACE.replace("bounded=0", "bounded=1"),
            GOOD_TRACE.replace("target_completed=1", "target_completed=0"),
            GOOD_TRACE.replace("copyin-errors=0", "copyin-errors=1"),
            format!(
                "{GOOD_TRACE}SHAPE1|complete|bounded=0|target_completed=1|target_exit_reason=1\n"
            ),
            format!("SHAPE1|fork|parent=12|child=11\n{GOOD_TRACE}"),
            GOOD_TRACE.replace("PC 11 0x2000 4", "PC 11 0x2000"),
            GOOD_TRACE.replace("SHAPE1|samples=9", "SHAPE1|samples=10"),
        ];

        for mutation in mutations {
            assert!(
                parse_trace(mutation.as_bytes()).is_err(),
                "accepted:\n{mutation}"
            );
        }
    }

    fn write_snapshot(dir: &std::path::Path, stem: &str, pid: u32, base: u64, words: &[u32]) {
        let code = words
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect::<Vec<_>>();
        std::fs::write(dir.join(format!("{stem}.bin")), &code).expect("write snapshot bytes");
        let metadata = serde_json::json!({
            "schema": "carrick.code-snapshot.v4",
            "pid": pid,
            "cache_base": base,
            "code_len": code.len(),
            "code_sha256": format!("{:x}", Sha256::digest(&code)),
            "blocks": [[0x4000, base]],
        });
        std::fs::write(
            dir.join(format!("{stem}.json")),
            serde_json::to_vec(&metadata).expect("serialize snapshot metadata"),
        )
        .expect("write snapshot metadata");
    }

    #[test]
    fn snapshot_loader_rejects_missing_or_unauthenticated_payloads() {
        let cases = ["missing", "schema", "length", "hash"];
        for case in cases {
            let dir = tempfile::tempdir().expect("snapshot tempdir");
            write_snapshot(dir.path(), "10-1", 10, 0x1000, &[0xd503_201f]);
            let json_path = dir.path().join("10-1.json");
            let bin_path = dir.path().join("10-1.bin");
            match case {
                "missing" => std::fs::remove_file(bin_path).expect("remove payload"),
                "schema" => {
                    let mut value: serde_json::Value =
                        serde_json::from_slice(&std::fs::read(&json_path).expect("read metadata"))
                            .expect("parse metadata");
                    value["schema"] = "old".into();
                    std::fs::write(json_path, serde_json::to_vec(&value).unwrap()).unwrap();
                }
                "length" => std::fs::write(bin_path, []).expect("truncate payload"),
                "hash" => std::fs::write(bin_path, 1_u32.to_le_bytes()).expect("mutate payload"),
                _ => unreachable!(),
            }
            assert!(
                load_snapshots(dir.path()).is_err(),
                "accepted {case} payload"
            );
        }
    }

    #[test]
    fn resolver_requires_one_own_or_one_ancestor_snapshot() {
        let dir = tempfile::tempdir().expect("snapshot tempdir");
        write_snapshot(dir.path(), "10-1", 10, 0x1000, &[0xf942_3791]);
        write_snapshot(dir.path(), "11-1", 11, 0x3000, &[0xd503_201f]);
        let snapshots = load_snapshots(dir.path()).expect("load snapshots");
        let parents = BTreeMap::from([(11, 10)]);
        let inherited = resolve_sample(
            PcSample {
                pid: 11,
                pc: 0x1000,
                count: 4,
            },
            &snapshots,
            &parents,
        )
        .expect("resolve inherited sample");
        assert_eq!(inherited.word, 0xf942_3791);
        assert!(inherited.inherited);

        assert!(
            resolve_sample(
                PcSample {
                    pid: 12,
                    pc: 0x1000,
                    count: 1,
                },
                &snapshots,
                &parents,
            )
            .is_err()
        );
        assert!(
            resolve_sample(
                PcSample {
                    pid: 11,
                    pc: 0x2000,
                    count: 1,
                },
                &snapshots,
                &parents,
            )
            .is_err()
        );
    }

    #[test]
    fn resolver_rejects_ambiguous_own_or_ancestor_ranges() {
        let own_dir = tempfile::tempdir().expect("own tempdir");
        write_snapshot(own_dir.path(), "10-1", 10, 0x1000, &[0xd503_201f]);
        write_snapshot(own_dir.path(), "10-2", 10, 0x1000, &[0xd65f_03c0]);
        let own = load_snapshots(own_dir.path()).expect("load own snapshots");
        assert!(
            resolve_sample(
                PcSample {
                    pid: 10,
                    pc: 0x1000,
                    count: 1,
                },
                &own,
                &BTreeMap::new(),
            )
            .is_err()
        );

        let ancestor_dir = tempfile::tempdir().expect("ancestor tempdir");
        write_snapshot(ancestor_dir.path(), "9-1", 9, 0x1000, &[0xd503_201f]);
        write_snapshot(ancestor_dir.path(), "10-1", 10, 0x1000, &[0xd65f_03c0]);
        write_snapshot(ancestor_dir.path(), "11-1", 11, 0x3000, &[0xd503_201f]);
        let ancestors = load_snapshots(ancestor_dir.path()).expect("load ancestor snapshots");
        let parents = BTreeMap::from([(10, 9), (11, 10)]);
        assert!(
            resolve_sample(
                PcSample {
                    pid: 11,
                    pc: 0x1000,
                    count: 1,
                },
                &ancestors,
                &parents,
            )
            .is_err()
        );
    }

    #[test]
    fn decodes_only_exact_64_bit_context_rows() {
        let cases = [
            (0xf942_3791, Direction::Load, 1128, 17),
            (0xf902_3791, Direction::Store, 1128, 17),
            (0xf942_5793, Direction::Load, 1192, 19),
            (0xf942_7f8f, Direction::Load, 1272, 15),
            (0xf942_478f, Direction::Load, 1160, 15),
        ];
        for (word, direction, slot, register) in cases {
            let row = decode_context64(word).expect("context access");
            assert_eq!(
                (row.direction, row.slot, row.register),
                (direction, slot, register)
            );
        }
        assert_eq!(decode_context64(0xf940_0020), None);
        assert_eq!(decode_context64(0xb940_0380), None);
    }

    #[test]
    fn full_report_binds_inputs_and_counts_inherited_samples() {
        let dir = tempfile::tempdir().expect("snapshot tempdir");
        write_snapshot(dir.path(), "10-1", 10, 0x1000, &[0xf942_3791]);
        write_snapshot(dir.path(), "11-1", 11, 0x3000, &[0xd503_201f]);
        let trace = GOOD_TRACE.replace("0x2000", "0x1000");

        let report = build_report(trace.as_bytes(), dir.path(), 0.5).expect("build report");

        assert_eq!(report.schema, "carrick.jit-shape-census.v1");
        assert_eq!(
            report.inputs.trace_sha256,
            format!("{:x}", Sha256::digest(trace.as_bytes()))
        );
        assert_eq!(report.inputs.snapshot_manifest_sha256.len(), 64);
        assert_eq!(report.coverage.own_samples, 3);
        assert_eq!(report.coverage.inherited_samples, 4);
        assert_eq!(report.coverage.missing_samples, 0);
        assert_eq!(report.coverage.matched_jit_samples, 7);
        assert_eq!(report.context_rows.len(), 1);
        assert_eq!(report.context_rows[0].key, "load:slot=1128:x17");
        assert_eq!(report.context_rows[0].samples, 7);
        assert_eq!(report.context_rows[0].projected_share_of_total_cpu, 0.5);

        std::fs::write(dir.path().join("10-1.bin"), 1_u32.to_le_bytes()).expect("mutate snapshot");
        assert!(build_report(trace.as_bytes(), dir.path(), 0.5).is_err());
    }
}
