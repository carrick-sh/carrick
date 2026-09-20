//! Strict reader for the complete low-rate HVPatch carrier user-stack profile.
//!
//! The D program emits one END aggregation. Its scalar `sample-population` is
//! authoritative only when every emitted stack count closes exactly to it.

use std::collections::{BTreeMap, BTreeSet, btree_map::Entry};
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};
use sha2::{Digest, Sha256};

use crate::trace_profile::ProfileCaptureStatus;

const PREFIX: &str = "HVPCARRIERLOW";
pub(crate) const PROGRAM_SHA256_PLACEHOLDER: &str = "/* CARRICK_HVPCARRIERLOW_PROGRAM_SHA256 */";

/// Render the bundled template's immutable digest into the raw-stream header.
/// The digest is of the unrendered template, as in AMP1, so a capture from an
/// edited `--script` cannot authenticate itself.
pub(crate) fn render_profile_script(template: &str) -> Result<String> {
    let slots = template.match_indices(PROGRAM_SHA256_PLACEHOLDER).count();
    if slots != 1 {
        bail!(
            "{PREFIX} profile template must contain exactly one program-SHA-256 placeholder, found {slots}"
        );
    }
    Ok(template.replacen(PROGRAM_SHA256_PLACEHOLDER, &program_sha256(), 1))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct HvpatchCarrierCpuLowRateSummary {
    pub(crate) sample_population: u64,
    pub(crate) stack_population: u64,
    pub(crate) stack_count: u64,
    pub(crate) program_sha256: String,
    /// Runtime `__TEXT` base of the traced carrier (`atos -l` input).
    pub(crate) image_text_base: String,
    pub(crate) raw: String,
}

impl HvpatchCarrierCpuLowRateSummary {
    pub(crate) fn from_path(path: &Path, status: ProfileCaptureStatus) -> Result<Self> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("read HVPatch carrier low-rate stream {}", path.display()))?;
        Self::from_raw(raw, status)
    }

    pub(crate) fn from_raw(raw: String, status: ProfileCaptureStatus) -> Result<Self> {
        require_lossless(status)?;

        let mut summary = None;
        let mut header = None;
        let mut population = None;
        let mut image_text_base = None;
        let mut section_seen = false;
        let mut stack_frames = 0_u64;
        let mut stack_count = 0_u64;
        let mut stack_population = 0_u64;

        for line in raw.lines() {
            if !section_seen {
                if line.is_empty() {
                    continue;
                }
                let record = Record::parse(line)?;
                match record.tag.as_str() {
                    "header" => {
                        record.exact_fields(&["program_sha256"])?;
                        if header
                            .replace(record.value("program_sha256")?.to_owned())
                            .is_some()
                        {
                            bail!("duplicate {PREFIX} header");
                        }
                    }
                    "summary" => {
                        if summary.replace(Summary::parse(&record)?).is_some() {
                            bail!("duplicate {PREFIX} summary");
                        }
                    }
                    "sample-population" => {
                        record.exact_fields(&["count"])?;
                        if population.replace(record.u64("count")?).is_some() {
                            bail!("duplicate {PREFIX} sample-population");
                        }
                    }
                    "image" => {
                        // Exact Mach-O identity of the traced carrier, so the
                        // retained raw stacks can be symbolicated offline.
                        record.exact_fields(&["host_pid", "text_base", "slide"])?;
                        if image_text_base
                            .replace(record.value("text_base")?.to_owned())
                            .is_some()
                        {
                            bail!("duplicate {PREFIX} image");
                        }
                    }
                    "section=user-stacks" => {
                        record.exact_fields(&[])?;
                        section_seen = true;
                    }
                    other => bail!("unknown {PREFIX} record tag {other:?}"),
                }
                continue;
            }

            if line.starts_with(PREFIX) {
                bail!("{PREFIX} record appears after the user-stacks section");
            }
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if is_canonical_u64(trimmed) {
                if stack_frames == 0 {
                    bail!("{PREFIX} stack count has no preceding user-stack frames");
                }
                let count = parse_u64(trimmed, "stack count")?;
                if count == 0 {
                    bail!("{PREFIX} emitted a zero-count user stack");
                }
                stack_population = stack_population
                    .checked_add(count)
                    .ok_or_else(|| anyhow!("{PREFIX} stack count overflow"))?;
                stack_count = stack_count
                    .checked_add(1)
                    .ok_or_else(|| anyhow!("{PREFIX} stack cardinality overflow"))?;
                stack_frames = 0;
            } else {
                stack_frames = stack_frames
                    .checked_add(1)
                    .ok_or_else(|| anyhow!("{PREFIX} stack frame count overflow"))?;
            }
        }

        let header = header.ok_or_else(|| anyhow!("{PREFIX} stream has no header"))?;
        if header != program_sha256() {
            bail!(
                "{PREFIX} header program_sha256 {header} does not name the bundled carrier low-rate program ({})",
                program_sha256()
            );
        }
        let summary = summary.ok_or_else(|| anyhow!("{PREFIX} stream has no summary"))?;
        let sample_population =
            population.ok_or_else(|| anyhow!("{PREFIX} stream has no sample-population"))?;
        if !section_seen {
            bail!("{PREFIX} stream has no user-stacks section");
        }
        if stack_frames != 0 {
            bail!("{PREFIX} user-stack aggregation ends without its count");
        }
        summary.validate()?;
        if sample_population == 0 || stack_count == 0 {
            bail!("{PREFIX} captured no user-stack population");
        }
        if stack_population != sample_population {
            bail!(
                "{PREFIX} stack-count closure failed: sample-population={sample_population}, user-stack-counts={stack_population}"
            );
        }

        let image_text_base = image_text_base
            .ok_or_else(|| anyhow!("{PREFIX} stream has no carrier image record"))?;

        Ok(Self {
            sample_population,
            stack_population,
            stack_count,
            program_sha256: program_sha256(),
            image_text_base,
            raw,
        })
    }

    pub(crate) fn render_human(&self) -> String {
        format!(
            "HVPatch carrier low-rate CPU: samples={}, user_stacks={}, stack_count_closure={}, bundled_program_sha256={}, image_text_base={}, raw_bytes={}",
            self.sample_population,
            self.stack_count,
            self.stack_population,
            self.program_sha256,
            self.image_text_base,
            self.raw.len(),
        )
    }
}

fn program_sha256() -> String {
    format!(
        "{:x}",
        Sha256::digest(
            carrick_runtime::dtrace_consumer::BUNDLED_HVPATCH_CARRIER_CPU_LOW_RATE_D.as_bytes(),
        )
    )
}

#[derive(Debug)]
struct Record {
    tag: String,
    fields: BTreeMap<String, String>,
}

impl Record {
    fn parse(line: &str) -> Result<Self> {
        let mut parts = line.split('|');
        if parts.next() != Some(PREFIX) {
            bail!("unknown {PREFIX} protocol prefix in {line:?}");
        }
        let tag = parts
            .next()
            .filter(|tag| !tag.is_empty())
            .ok_or_else(|| anyhow!("truncated {PREFIX} record"))?
            .to_owned();
        let mut fields = BTreeMap::new();
        for raw in parts {
            let (key, value) = raw
                .split_once('=')
                .ok_or_else(|| anyhow!("{PREFIX} field lacks '=': {raw:?}"))?;
            if key.is_empty() || value.is_empty() {
                bail!("{PREFIX} field has an empty key or value");
            }
            match fields.entry(key.to_owned()) {
                Entry::Vacant(slot) => {
                    slot.insert(value.to_owned());
                }
                Entry::Occupied(_) => bail!("duplicate {PREFIX} field {key:?}"),
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
            bail!("{PREFIX} {:?} field contract mismatch", self.tag);
        }
        Ok(())
    }

    fn value(&self, field: &str) -> Result<&str> {
        self.fields
            .get(field)
            .map(String::as_str)
            .ok_or_else(|| anyhow!("{PREFIX} {:?} record lacks {field:?}", self.tag))
    }

    fn u64(&self, field: &str) -> Result<u64> {
        parse_u64(self.value(field)?, field)
    }
}

#[derive(Clone, Copy, Debug)]
struct Summary {
    root_exited: u64,
    bounded: u64,
    errors: u64,
    saw_sample: u64,
}

impl Summary {
    fn parse(record: &Record) -> Result<Self> {
        record.exact_fields(&["status", "root_exited", "bounded", "errors", "saw_sample"])?;
        if record.value("status")? != "ok" {
            bail!("{PREFIX} producer reported an error");
        }
        Ok(Self {
            root_exited: record.u64("root_exited")?,
            bounded: record.u64("bounded")?,
            errors: record.u64("errors")?,
            saw_sample: record.u64("saw_sample")?,
        })
    }

    fn validate(self) -> Result<()> {
        if self.root_exited != 1 || self.bounded != 0 || self.errors != 0 || self.saw_sample != 1 {
            bail!(
                "{PREFIX} producer summary is not a clean completed capture: root_exited={}, bounded={}, errors={}, saw_sample={}",
                self.root_exited,
                self.bounded,
                self.errors,
                self.saw_sample,
            );
        }
        Ok(())
    }
}

fn is_canonical_u64(value: &str) -> bool {
    value == "0" || (!value.starts_with('0') && value.bytes().all(|byte| byte.is_ascii_digit()))
}

fn parse_u64(value: &str, field: &str) -> Result<u64> {
    if !is_canonical_u64(value) {
        bail!("{PREFIX} {field} is not a canonical unsigned integer: {value:?}");
    }
    value
        .parse()
        .with_context(|| format!("invalid {PREFIX} {field}"))
}

fn require_lossless(status: ProfileCaptureStatus) -> Result<()> {
    if status != ProfileCaptureStatus::default() {
        bail!(
            "{PREFIX} capture is not lossless: principal={}, aggregation={}, dynamic={}, dynamic_rinse={}, dynamic_dirty={}, other={}, interrupted={}",
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
