//! Strict reader for the HVPatch live-core lifecycle DTrace protocol.

use std::collections::{BTreeMap, BTreeSet, btree_map::Entry};
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};
use sha2::{Digest, Sha256};

use crate::trace_profile::ProfileCaptureStatus;

const PREFIX: &str = "HVPATCHCORE1";

#[derive(Debug)]
struct Record {
    tag: String,
    fields: BTreeMap<String, String>,
}

impl Record {
    fn parse(line: &str) -> Result<Self> {
        let mut parts = line.split('|');
        if parts.next() != Some(PREFIX) {
            bail!("unknown HVPatch core protocol prefix in {line:?}");
        }
        let tag = parts
            .next()
            .filter(|tag| !tag.is_empty())
            .ok_or_else(|| anyhow!("truncated HVPatch core record"))?
            .to_owned();
        let mut fields = BTreeMap::new();
        for raw in parts {
            let (key, value) = raw
                .split_once('=')
                .ok_or_else(|| anyhow!("HVPatch core field lacks '=': {raw:?}"))?;
            if key.is_empty() || value.is_empty() {
                bail!("HVPatch core field has an empty key or value");
            }
            match fields.entry(key.to_owned()) {
                Entry::Vacant(slot) => {
                    slot.insert(value.to_owned());
                }
                Entry::Occupied(_) => bail!("duplicate HVPatch core field {key:?}"),
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
            bail!(
                "HVPatch core {:?} field contract mismatch: missing={:?}, extra={:?}",
                self.tag,
                expected.difference(&actual).collect::<Vec<_>>(),
                actual.difference(&expected).collect::<Vec<_>>()
            );
        }
        Ok(())
    }

    fn value(&self, field: &str) -> Result<&str> {
        self.fields
            .get(field)
            .map(String::as_str)
            .ok_or_else(|| anyhow!("HVPatch core {:?} missing {field}", self.tag))
    }

    fn u64(&self, field: &str) -> Result<u64> {
        self.value(field)?
            .parse()
            .with_context(|| format!("parse HVPatch core {field}"))
    }

    fn i32(&self, field: &str) -> Result<i32> {
        self.value(field)?
            .parse()
            .with_context(|| format!("parse HVPatch core {field}"))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Identity {
    generation: u64,
    pid: i32,
    tid: i32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ContextRecord {
    generation: u64,
    mm: u64,
    asid: u64,
    required_threads: u64,
    collected_threads: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CensusRecord {
    generation: u64,
    mappings: u64,
    notes: u64,
    loads: u64,
    bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct HvpatchCoreSummary {
    pub(crate) generation: u64,
    pub(crate) pid: i32,
    pub(crate) tid: i32,
    pub(crate) threads: u64,
    pub(crate) bytes: u64,
}

impl HvpatchCoreSummary {
    pub(crate) fn from_path(
        path: &Path,
        artifact_path: &Path,
        status: ProfileCaptureStatus,
    ) -> Result<Self> {
        let contents = fs::read_to_string(path)
            .with_context(|| format!("read HVPatch core stream {}", path.display()))?;
        let artifact = fs::read(artifact_path).with_context(|| {
            format!(
                "read explicitly supplied HVPatch core artifact {}",
                artifact_path.display()
            )
        })?;
        crate::debug_core::validate_bytes(&artifact, &artifact_path.display().to_string())
            .map_err(|error| anyhow!("supplied HVPatch core artifact is invalid: {error}"))?;
        Self::from_lines(contents.lines(), &artifact, status)
    }

    fn from_lines<I, S>(lines: I, artifact: &[u8], status: ProfileCaptureStatus) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        if status != ProfileCaptureStatus::default() {
            bail!("HVPatch core capture is lossy or interrupted: {status:?}");
        }
        let mut stage = 0_u8;
        let mut identity = None;
        let mut context = None;
        let mut census = None;
        let mut hash = None;
        let mut summary = None;
        for raw in lines {
            let line = raw.as_ref();
            if line.is_empty() {
                continue;
            }
            if summary.is_some() {
                bail!("HVPatch core record appears after the terminal summary");
            }
            let record = Record::parse(line)?;
            match record.tag.as_str() {
                "header" => {
                    record.exact_fields(&["version"])?;
                    require_stage(stage, 0, "header")?;
                    if record.u64("version")? != 1 {
                        bail!("duplicate or unsupported HVPATCHCORE1 header");
                    }
                    stage = 1;
                }
                "lifecycle" => {
                    record.exact_fields(&["phase", "pid", "tid", "generation", "outcome"])?;
                    let phase = record.u64("phase")?;
                    let (expected_stage, next_stage) = match phase {
                        0 => (1, 2),
                        1 => (2, 3),
                        2 => (4, 5),
                        3 => (7, 8),
                        4 => (8, 9),
                        5 => (9, 10),
                        _ => bail!("invalid HVPatch core lifecycle phase {phase}"),
                    };
                    require_stage(stage, expected_stage, "lifecycle")?;
                    if record.u64("outcome")? != 0 {
                        bail!("HVPatch core lifecycle reports a failure outcome");
                    }
                    let observed = Identity {
                        generation: record.u64("generation")?,
                        pid: record.i32("pid")?,
                        tid: record.i32("tid")?,
                    };
                    join(&mut identity, observed, "lifecycle identity")?;
                    stage = next_stage;
                }
                "context" => {
                    require_stage(stage, 3, "context")?;
                    record.exact_fields(&[
                        "generation",
                        "mm",
                        "asid",
                        "required_threads",
                        "collected_threads",
                    ])?;
                    let observed = ContextRecord {
                        generation: record.u64("generation")?,
                        mm: record.u64("mm")?,
                        asid: record.u64("asid")?,
                        required_threads: record.u64("required_threads")?,
                        collected_threads: record.u64("collected_threads")?,
                    };
                    if context.replace(observed).is_some() {
                        bail!("duplicate HVPatch core context");
                    }
                    stage = 4;
                }
                "census" => {
                    require_stage(stage, 5, "census")?;
                    record.exact_fields(&["generation", "mappings", "notes", "loads", "bytes"])?;
                    let observed = CensusRecord {
                        generation: record.u64("generation")?,
                        mappings: record.u64("mappings")?,
                        notes: record.u64("notes")?,
                        loads: record.u64("loads")?,
                        bytes: record.u64("bytes")?,
                    };
                    if census.replace(observed).is_some() {
                        bail!("duplicate HVPatch core census");
                    }
                    stage = 6;
                }
                "hash" => {
                    require_stage(stage, 6, "hash")?;
                    record.exact_fields(&["generation", "sha256"])?;
                    let digest = record.value("sha256")?;
                    if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                        bail!("HVPatch core hash is not a SHA-256 digest");
                    }
                    if hash
                        .replace((record.u64("generation")?, digest.to_owned()))
                        .is_some()
                    {
                        bail!("duplicate HVPatch core hash");
                    }
                    stage = 7;
                }
                "summary" => {
                    require_stage(stage, 10, "summary")?;
                    let fields = [
                        "status",
                        "lifecycle",
                        "requests",
                        "quiesced",
                        "snapshots",
                        "serialized",
                        "published",
                        "committed",
                        "failed",
                        "contexts",
                        "censuses",
                        "hashes",
                        "generation",
                        "pid",
                        "tid",
                        "mm",
                        "asid",
                        "required_threads",
                        "collected_threads",
                        "mappings",
                        "notes",
                        "loads",
                        "bytes",
                        "identity_drift",
                        "join_drift",
                        "order_errors",
                        "bounded",
                        "errors",
                        "drops",
                        "target_exit_seen",
                        "target_exit_code",
                        "target_exit_reason",
                    ];
                    record.exact_fields(&fields)?;
                    if summary.replace(record).is_some() {
                        bail!("duplicate HVPatch core summary");
                    }
                    stage = 11;
                }
                other => bail!("unknown HVPatch core record {other:?}"),
            }
        }
        if stage != 11 {
            bail!("HVPatch core stream is incomplete or temporally out of order");
        }
        let identity = identity.ok_or_else(|| anyhow!("HVPatch core identity is absent"))?;
        let context = context.ok_or_else(|| anyhow!("HVPatch core context is absent"))?;
        let census = census.ok_or_else(|| anyhow!("HVPatch core census is absent"))?;
        let (hash_generation, recorded_hash) =
            hash.ok_or_else(|| anyhow!("HVPatch core hash is absent"))?;
        let artifact_hash = format!("{:x}", Sha256::digest(artifact));
        if identity.generation == 0
            || identity.pid <= 0
            || identity.tid <= 0
            || context.generation != identity.generation
            || census.generation != identity.generation
            || hash_generation != identity.generation
            || context.mm == 0
            || context.asid == 0
            || context.required_threads < 3
            || context.collected_threads != context.required_threads
            || census.mappings == 0
            || census.loads == 0
            || census.bytes == 0
            || usize::try_from(census.bytes).ok() != Some(artifact.len())
            || census.notes != 4 + 3 * context.collected_threads
        {
            bail!("HVPatch core joined authority is incomplete or out of generation");
        }
        if !recorded_hash.eq_ignore_ascii_case(&artifact_hash) {
            bail!("HVPatch core receipt digest does not authenticate the supplied artifact");
        }
        let summary = summary.ok_or_else(|| anyhow!("HVPatch core summary is absent"))?;
        validate_summary(&summary, identity, context, census)?;
        Ok(Self {
            generation: identity.generation,
            pid: identity.pid,
            tid: identity.tid,
            threads: context.collected_threads,
            bytes: census.bytes,
        })
    }

    pub(crate) fn render_human(self) -> String {
        format!(
            "HVPatch core: generation={}, pid={}, tid={}, threads={}, bytes={}",
            self.generation, self.pid, self.tid, self.threads, self.bytes
        )
    }
}

fn require_stage(actual: u8, expected: u8, record: &str) -> Result<()> {
    if actual != expected {
        bail!(
            "HVPatch core {record} is temporally out of order (stage {actual}, expected {expected})"
        );
    }
    Ok(())
}

fn join<T: Copy + Eq>(slot: &mut Option<T>, value: T, name: &str) -> Result<()> {
    if slot.is_some_and(|prior| prior != value) {
        bail!("HVPatch core {name} drifted");
    }
    *slot = Some(value);
    Ok(())
}

fn validate_summary(
    record: &Record,
    identity: Identity,
    context: ContextRecord,
    census: CensusRecord,
) -> Result<()> {
    if record.value("status")? != "ok"
        || record.u64("lifecycle")? != 6
        || [
            "requests",
            "quiesced",
            "snapshots",
            "serialized",
            "published",
            "committed",
            "contexts",
            "censuses",
            "hashes",
            "target_exit_seen",
        ]
        .iter()
        .any(|field| record.u64(field).ok() != Some(1))
        || [
            "failed",
            "identity_drift",
            "join_drift",
            "order_errors",
            "bounded",
            "errors",
            "drops",
            "target_exit_code",
        ]
        .iter()
        .any(|field| record.u64(field).ok() != Some(0))
        || record.u64("generation")? != identity.generation
        || record.i32("pid")? != identity.pid
        || record.i32("tid")? != identity.tid
        || record.u64("mm")? != context.mm
        || record.u64("asid")? != context.asid
        || record.u64("required_threads")? != context.required_threads
        || record.u64("collected_threads")? != context.collected_threads
        || record.u64("mappings")? != census.mappings
        || record.u64("notes")? != census.notes
        || record.u64("loads")? != census.loads
        || record.u64("bytes")? != census.bytes
    {
        bail!("HVPatch core producer summary is not a clean joined capture");
    }
    if record.i32("target_exit_reason")? <= 0 {
        bail!("HVPatch core target exit reason is absent");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn artifact() -> Vec<u8> {
        vec![0x5a; 4096]
    }

    fn lifecycle(phase: u8) -> String {
        format!("HVPATCHCORE1|lifecycle|phase={phase}|pid=5|tid=5|generation=1|outcome=0")
    }

    fn valid(artifact: &[u8]) -> Vec<String> {
        vec![
            "HVPATCHCORE1|header|version=1".to_owned(),
            lifecycle(0),
            lifecycle(1),
            "HVPATCHCORE1|context|generation=1|mm=7|asid=2|required_threads=3|collected_threads=3".to_owned(),
            lifecycle(2),
            "HVPATCHCORE1|census|generation=1|mappings=4|notes=13|loads=8|bytes=4096".to_owned(),
            format!(
                "HVPATCHCORE1|hash|generation=1|sha256={:x}",
                Sha256::digest(artifact)
            ),
            lifecycle(3),
            lifecycle(4),
            lifecycle(5),
            "HVPATCHCORE1|summary|status=ok|lifecycle=6|requests=1|quiesced=1|snapshots=1|serialized=1|published=1|committed=1|failed=0|contexts=1|censuses=1|hashes=1|generation=1|pid=5|tid=5|mm=7|asid=2|required_threads=3|collected_threads=3|mappings=4|notes=13|loads=8|bytes=4096|identity_drift=0|join_drift=0|order_errors=0|bounded=0|errors=0|drops=0|target_exit_seen=1|target_exit_code=0|target_exit_reason=1".to_owned(),
        ]
    }

    fn parse(lines: Vec<String>, artifact: &[u8]) -> Result<HvpatchCoreSummary> {
        HvpatchCoreSummary::from_lines(lines, artifact, ProfileCaptureStatus::default())
    }

    #[test]
    fn accepts_one_complete_joined_generation() {
        let artifact = artifact();
        let summary = parse(valid(&artifact), &artifact).expect("valid core stream");
        assert_eq!(summary.threads, 3);
    }

    #[test]
    fn rejects_every_missing_or_duplicate_record_class() {
        let artifact = artifact();
        for needle in [
            "|header|",
            "|lifecycle|phase=4",
            "|context|",
            "|census|",
            "|hash|",
            "|summary|",
        ] {
            let lines = valid(&artifact)
                .into_iter()
                .filter(|line| !line.contains(needle))
                .collect::<Vec<_>>();
            assert!(parse(lines, &artifact).is_err());

            let mut duplicate = valid(&artifact);
            let record = duplicate
                .iter()
                .find(|line| line.contains(needle))
                .expect("record class")
                .clone();
            duplicate.push(record);
            assert!(parse(duplicate, &artifact).is_err());
        }
    }

    #[test]
    fn rejects_loss_generation_drift_and_producer_failure() {
        let artifact = artifact();
        let lossy = ProfileCaptureStatus {
            principal_drops: 1,
            ..ProfileCaptureStatus::default()
        };
        assert!(HvpatchCoreSummary::from_lines(valid(&artifact), &artifact, lossy).is_err());
        let drift = valid(&artifact)
            .into_iter()
            .map(|line| {
                if line.contains("|context|") {
                    line.replace("generation=1", "generation=2")
                } else {
                    line
                }
            })
            .collect::<Vec<_>>();
        assert!(parse(drift, &artifact).is_err());
        let failed = valid(&artifact)
            .into_iter()
            .map(|line| line.replace("status=ok", "status=error"))
            .collect::<Vec<_>>();
        assert!(parse(failed, &artifact).is_err());
    }

    #[test]
    fn rejects_zero_incomplete_bounded_and_failed_authority() {
        let artifact = artifact();
        for (from, to) in [
            ("generation=1", "generation=0"),
            ("required_threads=3", "required_threads=0"),
            ("collected_threads=3", "collected_threads=2"),
            ("bounded=0", "bounded=1"),
            ("errors=0", "errors=1"),
            ("drops=0", "drops=1"),
            ("order_errors=0", "order_errors=1"),
            ("outcome=0", "outcome=1"),
        ] {
            let malformed = valid(&artifact)
                .into_iter()
                .map(|line| line.replace(from, to))
                .collect::<Vec<_>>();
            assert!(
                parse(malformed, &artifact).is_err(),
                "accepted {from} -> {to}"
            );
        }
    }

    #[test]
    fn rejects_temporal_reordering_and_requires_an_exit_reason() {
        let artifact = artifact();
        let mut reordered = valid(&artifact);
        reordered.swap(2, 3);
        assert!(parse(reordered, &artifact).is_err());

        let no_reason = valid(&artifact)
            .into_iter()
            .map(|line| line.replace("target_exit_reason=1", "target_exit_reason=0"))
            .collect::<Vec<_>>();
        assert!(parse(no_reason, &artifact).is_err());
    }

    #[test]
    fn rejects_syntactically_valid_arbitrary_digest_and_artifact_mutation() {
        let artifact = artifact();
        let arbitrary = valid(&artifact)
            .into_iter()
            .map(|line| {
                if line.contains("|hash|") {
                    format!("HVPATCHCORE1|hash|generation=1|sha256={}", "ab".repeat(32))
                } else {
                    line
                }
            })
            .collect();
        assert!(parse(arbitrary, &artifact).is_err());

        let mut changed_artifact = artifact.clone();
        changed_artifact[0] ^= 1;
        assert!(parse(valid(&artifact), &changed_artifact).is_err());
    }
}
