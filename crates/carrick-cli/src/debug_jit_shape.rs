//! Fail-closed offline join for sampled native-DSR JIT PCs.

use std::collections::BTreeMap;
#[cfg(test)]
use std::collections::BTreeSet;
use std::fs;
use std::io::{BufWriter, Write};
use std::path::Path;

use anyhow::{Context, anyhow, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tempfile::NamedTempFile;

use crate::jit_shape_snapshot::ResolutionOrigin;
use crate::native_shape_profile::{
    CaptureIdentity, NativeShapeAuthority, NativeShapeCounts, NativeShapeRaw,
    load_snapshot_set_from_real_directory, parse_accepted_capture_receipt,
};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Direction {
    Load,
    Store,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ContextOperandAccess {
    slot: i64,
    register: u8,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ContextAccess {
    direction: Direction,
    first: ContextOperandAccess,
    second: Option<ContextOperandAccess>,
}

#[derive(
    Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize,
)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum EvidenceClass {
    InsertedExact,
    ExactAmbiguous,
    GuestDescriptive,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct Classification {
    evidence_class: EvidenceClass,
    family: &'static str,
}

pub(crate) const CENSUS_SCHEMA: &str = "carrick.jit-shape-census.v3";
pub(crate) const CLASSIFIER_SCHEMA: &str = "carrick.jit-shape-classifier.aarch64.v3";

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CensusFraction {
    pub(crate) numerator: u64,
    pub(crate) denominator: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CensusShare {
    pub(crate) samples: u64,
    pub(crate) share_of_jit: CensusFraction,
    pub(crate) share_of_all_cpu: CensusFraction,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CensusPopulations {
    pub(crate) all_cpu: u64,
    pub(crate) user_cpu: u64,
    pub(crate) kernel_cpu: u64,
    pub(crate) invalid_cpu: u64,
    pub(crate) jit_user: u64,
    pub(crate) non_jit_user: u64,
    pub(crate) pc_rows: u64,
    pub(crate) pc_samples: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CensusCoverage {
    pub(crate) resolved_samples: u64,
    pub(crate) own_samples: u64,
    pub(crate) inherited_samples: u64,
    pub(crate) missing_samples: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FamilyRow {
    pub(crate) evidence_class: EvidenceClass,
    pub(crate) family: String,
    pub(crate) share: CensusShare,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WordRow {
    pub(crate) evidence_class: EvidenceClass,
    pub(crate) family: String,
    pub(crate) word: u32,
    pub(crate) share: CensusShare,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ContextOperand {
    pub(crate) slot: i64,
    pub(crate) physical_register: u8,
    pub(crate) semantic_label: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ContextRow {
    pub(crate) direction: Direction,
    pub(crate) first: ContextOperand,
    pub(crate) second: Option<ContextOperand>,
    pub(crate) share: CensusShare,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct JitShapeCensusV3 {
    pub(crate) schema: String,
    pub(crate) capture_receipt_sha256: String,
    pub(crate) raw_trace_sha256: String,
    pub(crate) snapshot_manifest_sha256: String,
    pub(crate) capture_authority: NativeShapeAuthority,
    pub(crate) census_identity: CaptureIdentity,
    pub(crate) classifier_schema: String,
    pub(crate) populations: CensusPopulations,
    pub(crate) coverage: CensusCoverage,
    pub(crate) inserted_exact_floor: CensusShare,
    pub(crate) families: Vec<FamilyRow>,
    pub(crate) words: Vec<WordRow>,
    pub(crate) contexts: Vec<ContextRow>,
}

pub(crate) const COMPARISON_SCHEMA: &str = "carrick.jit-shape-comparison.v1";

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ComparisonDeterminants {
    pub(crate) a_capture_authority: NativeShapeAuthority,
    pub(crate) b_capture_authority: NativeShapeAuthority,
    pub(crate) a_census_identity: CaptureIdentity,
    pub(crate) b_census_identity: CaptureIdentity,
    pub(crate) classifier_schema: String,
    pub(crate) a_capture_receipt_sha256: String,
    pub(crate) b_capture_receipt_sha256: String,
    pub(crate) a_raw_trace_sha256: String,
    pub(crate) b_raw_trace_sha256: String,
    pub(crate) a_snapshot_manifest_sha256: String,
    pub(crate) b_snapshot_manifest_sha256: String,
    pub(crate) a_populations: CensusPopulations,
    pub(crate) b_populations: CensusPopulations,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum ComparisonKey {
    Family {
        evidence_class: EvidenceClass,
        family: String,
    },
    Word {
        family: String,
        word: u32,
        evidence_class: EvidenceClass,
    },
    Context {
        direction: Direction,
        first: ContextOperand,
        second: Option<ContextOperand>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ComparisonFraction {
    pub(crate) numerator: u128,
    pub(crate) denominator: u128,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ComparisonRow {
    pub(crate) key: ComparisonKey,
    pub(crate) a: CensusShare,
    pub(crate) b: CensusShare,
    pub(crate) absolute_all_cpu_drift: ComparisonFraction,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MechanicalCrossing {
    pub(crate) key: ComparisonKey,
    pub(crate) a: CensusShare,
    pub(crate) b: CensusShare,
    pub(crate) minimum_all_cpu_share: CensusFraction,
    pub(crate) absolute_all_cpu_drift: ComparisonFraction,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct JitShapeComparisonV1 {
    pub(crate) schema: String,
    pub(crate) a_sha256: String,
    pub(crate) b_sha256: String,
    pub(crate) determinants: ComparisonDeterminants,
    pub(crate) family_rows: Vec<ComparisonRow>,
    pub(crate) word_rows: Vec<ComparisonRow>,
    pub(crate) context_rows: Vec<ComparisonRow>,
    pub(crate) mechanical_crossings: Vec<MechanicalCrossing>,
}

impl ComparisonDeterminants {
    fn validate(&self) -> anyhow::Result<()> {
        self.a_capture_authority
            .sha256()
            .context("validate comparison capture A authority")?;
        self.b_capture_authority
            .sha256()
            .context("validate comparison capture B authority")?;
        self.a_census_identity
            .validate()
            .context("validate comparison census A identity")?;
        self.b_census_identity
            .validate()
            .context("validate comparison census B identity")?;
        if self.a_census_identity.host_arch != "aarch64"
            || self.b_census_identity.host_arch != "aarch64"
        {
            bail!("comparison census identities must both be aarch64");
        }

        let a = &self.a_capture_authority;
        let b = &self.b_capture_authority;
        for (same, label) in [
            (a.schema == b.schema, "capture authority schema"),
            (a.profile == b.profile, "capture profile"),
            (a.raw_schema == b.raw_schema, "raw schema"),
            (a.git_head == b.git_head, "capture git HEAD"),
            (a.git_dirty == b.git_dirty, "capture git dirty state"),
            (
                a.executable_sha256 == b.executable_sha256,
                "capture executable SHA-256",
            ),
            (a.host == b.host, "capture host"),
            (a.host_arch == b.host_arch, "capture architecture"),
            (a.os_build == b.os_build, "capture OS build"),
            (a.image == b.image, "canonical image"),
            (a.target_argv == b.target_argv, "target argv"),
            (
                a.target_argv_sha256 == b.target_argv_sha256,
                "target argv digest",
            ),
            (
                a.program_template_sha256 == b.program_template_sha256,
                "D template SHA-256",
            ),
            (a.sampling_hz == b.sampling_hz, "sampling frequency"),
            (
                self.a_census_identity.git_head == self.b_census_identity.git_head,
                "census git HEAD",
            ),
            (
                self.a_census_identity.git_dirty == self.b_census_identity.git_dirty,
                "census git dirty state",
            ),
            (
                self.a_census_identity.executable_sha256
                    == self.b_census_identity.executable_sha256,
                "census executable SHA-256",
            ),
            (
                self.a_census_identity.host == self.b_census_identity.host,
                "census host",
            ),
            (
                self.a_census_identity.host_arch == self.b_census_identity.host_arch,
                "census architecture",
            ),
            (
                self.a_census_identity.os_build == self.b_census_identity.os_build,
                "census OS build",
            ),
        ] {
            if !same {
                bail!("comparison {label} determinant drifted");
            }
        }
        if self.classifier_schema != CLASSIFIER_SCHEMA {
            bail!("comparison classifier schema is not {CLASSIFIER_SCHEMA}");
        }
        require_distinct(&a.run_id, &b.run_id, "run IDs")?;
        for (value, label) in [
            (&self.a_capture_receipt_sha256, "capture A receipt SHA-256"),
            (&self.b_capture_receipt_sha256, "capture B receipt SHA-256"),
            (&self.a_raw_trace_sha256, "raw trace A SHA-256"),
            (&self.b_raw_trace_sha256, "raw trace B SHA-256"),
            (
                &self.a_snapshot_manifest_sha256,
                "snapshot manifest A SHA-256",
            ),
            (
                &self.b_snapshot_manifest_sha256,
                "snapshot manifest B SHA-256",
            ),
        ] {
            validate_sha256(value, label)?;
        }
        require_distinct(
            &self.a_capture_receipt_sha256,
            &self.b_capture_receipt_sha256,
            "capture receipt hashes",
        )?;
        require_distinct(
            &self.a_raw_trace_sha256,
            &self.b_raw_trace_sha256,
            "raw trace hashes",
        )?;
        require_distinct(
            &self.a_snapshot_manifest_sha256,
            &self.b_snapshot_manifest_sha256,
            "snapshot manifest hashes",
        )?;
        validate_comparison_population(&self.a_populations, "A")?;
        validate_comparison_population(&self.b_populations, "B")?;
        Ok(())
    }
}

impl JitShapeComparisonV1 {
    pub(crate) fn validate(&self) -> anyhow::Result<()> {
        if self.schema != COMPARISON_SCHEMA {
            bail!("JIT shape comparison schema is not {COMPARISON_SCHEMA}");
        }
        validate_sha256(&self.a_sha256, "comparison census A SHA-256")?;
        validate_sha256(&self.b_sha256, "comparison census B SHA-256")?;
        require_distinct(&self.a_sha256, &self.b_sha256, "census hashes")?;
        self.determinants.validate()?;

        validate_comparison_rows(
            &self.family_rows,
            ComparisonRowKind::Family,
            &self.determinants,
        )?;
        validate_comparison_rows(&self.word_rows, ComparisonRowKind::Word, &self.determinants)?;
        validate_comparison_rows(
            &self.context_rows,
            ComparisonRowKind::Context,
            &self.determinants,
        )?;
        validate_comparison_populations(self)?;

        let expected_crossings = mechanical_crossings(
            self.family_rows
                .iter()
                .chain(&self.word_rows)
                .chain(&self.context_rows)
                .cloned(),
        )?;
        if self.mechanical_crossings != expected_crossings {
            bail!("comparison mechanical crossings are incomplete, incorrect, or out of order");
        }
        Ok(())
    }
}

impl JitShapeCensusV3 {
    pub(crate) fn validate(&self) -> anyhow::Result<()> {
        if self.schema != CENSUS_SCHEMA {
            bail!("JIT shape census schema is not {CENSUS_SCHEMA}");
        }
        if self.classifier_schema != CLASSIFIER_SCHEMA {
            bail!("JIT shape classifier schema is not {CLASSIFIER_SCHEMA}");
        }
        for (value, label) in [
            (&self.capture_receipt_sha256, "capture receipt SHA-256"),
            (&self.raw_trace_sha256, "raw trace SHA-256"),
            (&self.snapshot_manifest_sha256, "snapshot manifest SHA-256"),
        ] {
            validate_sha256(value, label)?;
        }
        self.capture_authority
            .sha256()
            .context("validate census capture authority")?;
        self.census_identity
            .validate()
            .context("validate census executor identity")?;
        if self.census_identity.host_arch != "aarch64" {
            bail!("native-shape census identity must be aarch64");
        }

        let populations = &self.populations;
        let classified_cpu = populations
            .user_cpu
            .checked_add(populations.kernel_cpu)
            .and_then(|value| value.checked_add(populations.invalid_cpu))
            .context("census CPU population overflow")?;
        if classified_cpu != populations.all_cpu
            || populations.invalid_cpu != 0
            || populations.jit_user.checked_add(populations.non_jit_user)
                != Some(populations.user_cpu)
            || populations.jit_user == 0
            || populations.pc_rows == 0
            || populations.pc_samples != populations.jit_user
            || populations.pc_samples < populations.pc_rows
        {
            bail!("census populations do not reconcile");
        }
        let resolved = self
            .coverage
            .own_samples
            .checked_add(self.coverage.inherited_samples)
            .context("census coverage overflow")?;
        if self.coverage.resolved_samples != resolved
            || self.coverage.resolved_samples != populations.jit_user
            || self.coverage.missing_samples != 0
        {
            bail!("census coverage does not reconcile");
        }

        let mut family_counts = BTreeMap::<(EvidenceClass, &str), u64>::new();
        let mut previous_family = None;
        for row in &self.families {
            if row.family.is_empty() {
                bail!("census family name is empty");
            }
            let key = (row.evidence_class, row.family.as_str());
            if previous_family
                .as_ref()
                .is_some_and(|previous| previous >= &key)
            {
                bail!("census family rows are duplicate or out of order");
            }
            validate_share(&row.share, populations.jit_user, populations.all_cpu)?;
            if row.share.samples == 0 {
                bail!("census family row has zero samples");
            }
            family_counts.insert(key, row.share.samples);
            previous_family = Some(key);
        }
        if checked_sum(family_counts.values().copied(), "census family total")?
            != populations.jit_user
        {
            bail!("census family rows do not cover the JIT population");
        }

        let mut word_family_counts = BTreeMap::<(EvidenceClass, &str), u64>::new();
        let mut expected_context_counts = BTreeMap::<ContextAccess, u64>::new();
        let mut previous_word = None;
        for row in &self.words {
            if row.family.is_empty() {
                bail!("census word family is empty");
            }
            let key = (row.family.as_str(), row.word);
            if previous_word
                .as_ref()
                .is_some_and(|previous| previous >= &key)
            {
                bail!("census word rows are duplicate or out of order");
            }
            validate_share(&row.share, populations.jit_user, populations.all_cpu)?;
            if row.share.samples == 0 {
                bail!("census word row has zero samples");
            }
            let classification = classify(row.word);
            if classification.evidence_class != row.evidence_class
                || classification.family != row.family
            {
                bail!("census word row disagrees with the classifier");
            }
            checked_increment(
                word_family_counts
                    .entry((row.evidence_class, row.family.as_str()))
                    .or_default(),
                row.share.samples,
                "census word family total",
            )?;
            let is_context_family = is_context_family(&row.family);
            match (is_context_family, decode_context(row.word)) {
                (true, Some(access)) => checked_increment(
                    expected_context_counts.entry(access).or_default(),
                    row.share.samples,
                    "expected census context total",
                )?,
                (true, None) => {
                    bail!("context-classified census word did not decode as context traffic")
                }
                (false, Some(_)) => {
                    bail!("non-context census word decoded as context traffic")
                }
                (false, None) => {}
            }
            previous_word = Some(key);
        }
        if word_family_counts != family_counts {
            bail!("census word rows do not exactly reproduce family populations");
        }

        let mut actual_context_counts = BTreeMap::<ContextAccess, u64>::new();
        let mut previous_context = None;
        for row in &self.contexts {
            let first = validate_context_operand(&row.first, "first")?;
            let second = row
                .second
                .as_ref()
                .map(|operand| validate_context_operand(operand, "second"))
                .transpose()?;
            let key = ContextAccess {
                direction: row.direction,
                first,
                second,
            };
            if previous_context
                .as_ref()
                .is_some_and(|previous| previous >= &key)
            {
                bail!("census context rows are duplicate or out of order");
            }
            validate_share(&row.share, populations.jit_user, populations.all_cpu)?;
            if row.share.samples == 0 {
                bail!("census context row has zero samples");
            }
            actual_context_counts.insert(key, row.share.samples);
            previous_context = Some(key);
        }
        if actual_context_counts != expected_context_counts {
            bail!("census context rows do not exactly reproduce context instruction evidence");
        }

        let source_exclusive_samples = checked_sum(
            family_counts
                .iter()
                .filter(|((class, _), _)| *class == EvidenceClass::InsertedExact)
                .map(|(_, samples)| *samples),
            "census source-exclusive exact floor",
        )?;
        validate_share(
            &self.inserted_exact_floor,
            populations.jit_user,
            populations.all_cpu,
        )?;
        if self.inserted_exact_floor.samples != source_exclusive_samples {
            bail!("census source-exclusive exact floor includes or omits family samples");
        }
        Ok(())
    }
}

fn validate_share(share: &CensusShare, jit_user: u64, all_cpu: u64) -> anyhow::Result<()> {
    if share.share_of_jit.numerator != share.samples
        || share.share_of_jit.denominator != jit_user
        || share.share_of_all_cpu.numerator != share.samples
        || share.share_of_all_cpu.denominator != all_cpu
        || share.samples > jit_user
        || share.samples > all_cpu
    {
        bail!("census integer share does not match its populations");
    }
    Ok(())
}

fn validate_sha256(value: &str, label: &str) -> anyhow::Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        bail!("{label} is not an exact lowercase SHA-256 digest");
    }
    Ok(())
}

fn validate_context_operand(
    operand: &ContextOperand,
    position: &str,
) -> anyhow::Result<ContextOperandAccess> {
    if operand.physical_register > 31 {
        bail!("census {position} context physical register exceeds x31");
    }
    if operand.semantic_label != context_semantic_label(operand.slot) {
        bail!("census {position} context semantic label does not match its slot");
    }
    Ok(ContextOperandAccess {
        slot: operand.slot,
        register: operand.physical_register,
    })
}

fn context_operand(access: ContextOperandAccess) -> ContextOperand {
    ContextOperand {
        slot: access.slot,
        physical_register: access.register,
        semantic_label: context_semantic_label(access.slot).to_owned(),
    }
}

fn decode_context64(word: u32) -> Option<ContextAccess> {
    let direction = match word & 0xffc0_03e0 {
        0xf940_0380 => Direction::Load,
        0xf900_0380 => Direction::Store,
        _ => return None,
    };
    Some(ContextAccess {
        direction,
        first: ContextOperandAccess {
            slot: i64::from(((word >> 10) & 0xfff) * 8),
            register: (word & 0x1f) as u8,
        },
        second: None,
    })
}

fn is_context_family(family: &str) -> bool {
    matches!(
        family,
        "ctx-load64" | "ctx-store64" | "ctx-load32" | "ctx-store32" | "ctx-pair"
    )
}

fn decode_context(word: u32) -> Option<ContextAccess> {
    if let Some(access) = decode_context64(word) {
        return Some(access);
    }
    let direction = match word & 0xffc0_03e0 {
        0xb940_0380 => Direction::Load,
        0xb900_0380 => Direction::Store,
        0xa940_0380 => Direction::Load,
        0xa900_0380 => Direction::Store,
        _ => return None,
    };
    let is_pair = matches!(word & 0xffc0_03e0, 0xa940_0380 | 0xa900_0380);
    let slot = if is_pair {
        let immediate = i64::from((word >> 15) & 0x7f);
        let signed = if immediate & 0x40 == 0 {
            immediate
        } else {
            immediate - 0x80
        };
        signed * 8
    } else {
        i64::from(((word >> 10) & 0xfff) * 4)
    };
    let first = ContextOperandAccess {
        slot,
        register: (word & 0x1f) as u8,
    };
    let second = if is_pair {
        Some(ContextOperandAccess {
            slot: slot.checked_add(8)?,
            register: ((word >> 10) & 0x1f) as u8,
        })
    } else {
        None
    };
    Some(ContextAccess {
        direction,
        first,
        second,
    })
}

pub(crate) fn run_jit_shape_census(
    trace_path: &Path,
    capture_path: &Path,
    snapshot_dir: &Path,
    output_path: Option<&Path>,
) -> anyhow::Result<()> {
    let executable = std::env::current_exe().context("resolve running census executable")?;
    let stdout = std::io::stdout();
    let mut stdout = stdout.lock();
    run_jit_shape_census_with_identity_capture(
        trace_path,
        capture_path,
        snapshot_dir,
        output_path,
        &mut stdout,
        || CaptureIdentity::capture(&executable),
    )
}

fn checked_increment(total: &mut u64, count: u64, name: &str) -> anyhow::Result<()> {
    *total = total
        .checked_add(count)
        .with_context(|| format!("{name} overflow"))?;
    Ok(())
}

fn classify(word: u32) -> Classification {
    let (evidence_class, family) = if (word & 0xffc0_03e0) == 0xf900_0380 {
        (EvidenceClass::InsertedExact, "ctx-store64")
    } else if (word & 0xffc0_03e0) == 0xf940_0380 {
        (EvidenceClass::InsertedExact, "ctx-load64")
    } else if (word & 0xffc0_03e0) == 0xb900_0380 {
        (EvidenceClass::InsertedExact, "ctx-store32")
    } else if (word & 0xffc0_03e0) == 0xb940_0380 {
        (EvidenceClass::InsertedExact, "ctx-load32")
    } else if matches!(word & 0xffc0_03e0, 0xa900_0380 | 0xa940_0380) {
        (EvidenceClass::InsertedExact, "ctx-pair")
    } else if (word & 0xffff_fc00) == 0xc8df_fc00 {
        (EvidenceClass::ExactAmbiguous, "guard-ldar")
    } else if (word & 0xffc0_001f) == 0xd340_0012 {
        (EvidenceClass::InsertedExact, "window-ubfm-x18")
    } else if (word & 0xff00_001f) == 0xb400_0012 {
        (EvidenceClass::InsertedExact, "window-cbz-x18")
    } else if matches!(word & 0xffff_fc00, 0xb257_0000 | 0xb251_0000) {
        (EvidenceClass::ExactAmbiguous, "bias-orr")
    } else if (word & 0xffff_ffe0) == 0xd51b_4200 {
        (EvidenceClass::ExactAmbiguous, "nzcv-msr")
    } else if (word & 0xffff_ffe0) == 0xd53b_4200 {
        (EvidenceClass::ExactAmbiguous, "nzcv-mrs")
    } else if matches!(
        word & 0xff80_001f,
        0x5280_0011 | 0x7280_0011 | 0xd280_0011 | 0xf280_0011
    ) {
        (EvidenceClass::ExactAmbiguous, "x17-materialize")
    } else if matches!(
        word & 0xff80_001f,
        0x5280_0012 | 0x7280_0012 | 0xd280_0012 | 0xf280_0012
    ) {
        (EvidenceClass::InsertedExact, "x18-materialize")
    } else if word == 0xd61f_0220 {
        (EvidenceClass::InsertedExact, "br-x17")
    } else if ((word >> 5) & 0x1f) == 18 && (word & 0x0a00_0000) == 0x0800_0000 {
        (EvidenceClass::InsertedExact, "x18-based-ldst")
    } else {
        (EvidenceClass::GuestDescriptive, coarse_family(word))
    };
    Classification {
        evidence_class,
        family,
    }
}

fn coarse_family(word: u32) -> &'static str {
    let top8 = word >> 24;
    if (word & 0xffff_fc1f) == 0xd61f_0000 {
        "br-reg"
    } else if (word & 0xffff_fc1f) == 0xd65f_0000 {
        "ret"
    } else if (word & 0x7c00_0000) == 0x1400_0000 {
        "b/bl"
    } else if top8 == 0x54 {
        "b.cond"
    } else if matches!(top8, 0x34 | 0x35 | 0xb4 | 0xb5) {
        "cbz/cbnz"
    } else if matches!(top8, 0x36 | 0x37) {
        "tbz/tbnz"
    } else if (word & 0x3b00_0000) == 0x3900_0000 || (word & 0x3b20_0c00) == 0x3800_0400 {
        "ldst-imm"
    } else if (word & 0x3f00_0000) == 0x3d00_0000 {
        "ldst-simd"
    } else if (word & 0x3a00_0000) == 0x2800_0000 {
        "ldst-pair"
    } else if (word & 0x3b20_0c00) == 0x3820_0800 {
        "ldst-reg"
    } else if matches!(word & 0x1f00_0000, 0x1100_0000 | 0x0b00_0000) {
        "add/sub"
    } else if matches!(word & 0x1f80_0000, 0x1280_0000 | 0x1200_0000) {
        "mov/logic-imm"
    } else if (word & 0x1f00_0000) == 0x0a00_0000 {
        "logic-reg"
    } else if (word & 0x1f00_0000) == 0x1b00_0000 {
        "muladd"
    } else if matches!(word & 0x0f00_0000, 0x0e00_0000 | 0x0400_0000) {
        "simd"
    } else {
        "other"
    }
}

#[cfg(test)]
fn guest_registers(word: u32) -> Option<BTreeSet<u8>> {
    let top = word >> 24;
    let mut registers = BTreeSet::new();
    if (word & 0x7c00_0000) == 0x1400_0000 || top == 0x54 {
        return Some(registers);
    }
    if matches!(top, 0x34 | 0x35 | 0xb4 | 0xb5 | 0x36 | 0x37) {
        registers.insert((word & 0x1f) as u8);
        return Some(registers);
    }
    if (word & 0x0a00_0000) == 0x0800_0000 || (word & 0x1c00_0000) == 0x0800_0000 {
        registers.insert((word & 0x1f) as u8);
        registers.insert(((word >> 5) & 0x1f) as u8);
        if (word & 0x3a00_0000) == 0x2800_0000 {
            registers.insert(((word >> 10) & 0x1f) as u8);
        }
        if (word & 0x3b20_0c00) == 0x3820_0800 {
            registers.insert(((word >> 16) & 0x1f) as u8);
        }
        return Some(registers);
    }
    if matches!(
        word & 0x1f00_0000,
        0x1100_0000 | 0x0b00_0000 | 0x0a00_0000 | 0x1b00_0000
    ) {
        registers.insert((word & 0x1f) as u8);
        registers.insert(((word >> 5) & 0x1f) as u8);
        if matches!(word & 0x1f00_0000, 0x0b00_0000 | 0x0a00_0000 | 0x1b00_0000) {
            registers.insert(((word >> 16) & 0x1f) as u8);
        }
        return Some(registers);
    }
    if matches!(word & 0x1f80_0000, 0x1280_0000 | 0x1200_0000) {
        registers.insert((word & 0x1f) as u8);
        return Some(registers);
    }
    None
}

fn census_share(samples: u64, jit_user: u64, all_cpu: u64) -> CensusShare {
    CensusShare {
        samples,
        share_of_jit: CensusFraction {
            numerator: samples,
            denominator: jit_user,
        },
        share_of_all_cpu: CensusFraction {
            numerator: samples,
            denominator: all_cpu,
        },
    }
}

fn build_authenticated_census(
    raw_bytes: &[u8],
    receipt_bytes: &[u8],
    snapshot_directory: &Path,
    census_identity: &CaptureIdentity,
) -> anyhow::Result<JitShapeCensusV3> {
    census_identity
        .validate()
        .context("validate census source/binary identity")?;
    if census_identity.host_arch != "aarch64" {
        bail!("native-shape census identity must be aarch64");
    }

    let receipt = parse_accepted_capture_receipt(receipt_bytes)?;
    let authority = receipt
        .authority
        .as_ref()
        .context("accepted receipt lost capture authority")?;
    let expected_raw_sha256 = receipt
        .raw_trace_sha256
        .as_deref()
        .context("accepted receipt lost raw trace digest")?;
    let raw_trace_sha256 = format!("{:x}", Sha256::digest(raw_bytes));
    if raw_trace_sha256 != expected_raw_sha256 {
        bail!("raw trace SHA-256 does not match capture receipt");
    }
    let raw = NativeShapeRaw::parse(raw_bytes, authority)
        .context("parse authenticated native-shape raw trace")?;

    let snapshots = load_snapshot_set_from_real_directory(snapshot_directory)
        .context("load authenticated native-shape snapshots")?;
    let expected_manifest = receipt
        .snapshot_manifest
        .as_ref()
        .context("accepted receipt lost snapshot manifest")?;
    if snapshots.manifest() != expected_manifest {
        bail!("recomputed snapshot manifest does not match capture receipt");
    }

    let pc_rows = u64::try_from(raw.pc_samples.len()).context("PC row count exceeds u64")?;
    let recomputed_counts = NativeShapeCounts {
        all_cpu: raw.all_cpu,
        user_cpu: raw.user_cpu,
        kernel_cpu: raw.kernel_cpu,
        invalid_cpu: raw.invalid_cpu,
        jit_user: raw.jit_user,
        non_jit_user: raw.non_jit_user,
        pc_rows,
        pc_samples: raw.jit_user,
    };
    if receipt.counts.as_ref() != Some(&recomputed_counts) {
        bail!("recomputed raw populations do not match capture receipt");
    }
    if receipt.lifecycle.as_ref() != Some(&raw.lifecycle) {
        bail!("recomputed raw lifecycle does not match capture receipt");
    }

    let mut own_samples = 0_u64;
    let mut inherited_samples = 0_u64;
    let mut family_counts = BTreeMap::<(EvidenceClass, &'static str), u64>::new();
    let mut word_counts = BTreeMap::<(&'static str, u32), (EvidenceClass, u64)>::new();
    let mut context_counts = BTreeMap::<ContextAccess, u64>::new();

    for sample in &raw.pc_samples {
        let resolved = snapshots
            .resolve(sample.pid, sample.pc, &raw.parents)
            .with_context(|| {
                format!(
                    "resolve authenticated PC pid={} pc={:#x}",
                    sample.pid, sample.pc
                )
            })?;
        match resolved.origin {
            ResolutionOrigin::Own => {
                checked_increment(&mut own_samples, sample.count, "own coverage samples")?
            }
            ResolutionOrigin::Ancestor { .. } => checked_increment(
                &mut inherited_samples,
                sample.count,
                "inherited coverage samples",
            )?,
        }

        let classification = classify(resolved.word);
        checked_increment(
            family_counts
                .entry((classification.evidence_class, classification.family))
                .or_default(),
            sample.count,
            "family samples",
        )?;
        let word_entry = word_counts
            .entry((classification.family, resolved.word))
            .or_insert((classification.evidence_class, 0));
        if word_entry.0 != classification.evidence_class {
            bail!("one instruction word was assigned conflicting evidence classes");
        }
        checked_increment(&mut word_entry.1, sample.count, "word samples")?;

        let is_context_family = is_context_family(classification.family);
        match (is_context_family, decode_context(resolved.word)) {
            (true, Some(access)) => checked_increment(
                context_counts.entry(access).or_default(),
                sample.count,
                "context samples",
            )?,
            (true, None) => bail!("context-classified word did not decode as context traffic"),
            (false, Some(_)) => bail!("non-context family decoded as context traffic"),
            (false, None) => {}
        }
    }

    let resolved_samples = own_samples
        .checked_add(inherited_samples)
        .context("resolved sample total overflow")?;
    if resolved_samples != raw.jit_user {
        bail!("resolved sample population does not equal JIT user population");
    }
    let family_total = checked_sum(family_counts.values().copied(), "family population")?;
    if family_total != raw.jit_user {
        bail!("family population does not equal JIT user population");
    }
    let word_total = checked_sum(
        word_counts.values().map(|(_, samples)| *samples),
        "word population",
    )?;
    if word_total != raw.jit_user {
        bail!("word population does not equal JIT user population");
    }
    let context_family_total = checked_sum(
        family_counts
            .iter()
            .filter(|((_, family), _)| family.starts_with("ctx-"))
            .map(|(_, samples)| *samples),
        "context family population",
    )?;
    let context_total = checked_sum(context_counts.values().copied(), "context row population")?;
    if context_total != context_family_total {
        bail!("context rows do not equal the union of context families");
    }

    let source_exclusive_samples = checked_sum(
        family_counts
            .iter()
            .filter(|((class, _), _)| *class == EvidenceClass::InsertedExact)
            .map(|(_, samples)| *samples),
        "source-exclusive exact floor",
    )?;
    let families = family_counts
        .into_iter()
        .map(|((evidence_class, family), samples)| FamilyRow {
            evidence_class,
            family: family.to_owned(),
            share: census_share(samples, raw.jit_user, raw.all_cpu),
        })
        .collect();
    let words = word_counts
        .into_iter()
        .map(|((family, word), (evidence_class, samples))| WordRow {
            evidence_class,
            family: family.to_owned(),
            word,
            share: census_share(samples, raw.jit_user, raw.all_cpu),
        })
        .collect();
    let contexts = context_counts
        .into_iter()
        .map(|(access, samples)| ContextRow {
            direction: access.direction,
            first: context_operand(access.first),
            second: access.second.map(context_operand),
            share: census_share(samples, raw.jit_user, raw.all_cpu),
        })
        .collect();

    Ok(JitShapeCensusV3 {
        schema: CENSUS_SCHEMA.to_owned(),
        capture_receipt_sha256: format!("{:x}", Sha256::digest(receipt_bytes)),
        raw_trace_sha256,
        snapshot_manifest_sha256: snapshots.manifest().sha256.clone(),
        capture_authority: authority.clone(),
        census_identity: census_identity.clone(),
        classifier_schema: CLASSIFIER_SCHEMA.to_owned(),
        populations: CensusPopulations {
            all_cpu: raw.all_cpu,
            user_cpu: raw.user_cpu,
            kernel_cpu: raw.kernel_cpu,
            invalid_cpu: raw.invalid_cpu,
            jit_user: raw.jit_user,
            non_jit_user: raw.non_jit_user,
            pc_rows,
            pc_samples: raw.jit_user,
        },
        coverage: CensusCoverage {
            resolved_samples,
            own_samples,
            inherited_samples,
            missing_samples: 0,
        },
        inserted_exact_floor: census_share(source_exclusive_samples, raw.jit_user, raw.all_cpu),
        families,
        words,
        contexts,
    })
}

fn checked_sum(values: impl IntoIterator<Item = u64>, label: &str) -> anyhow::Result<u64> {
    values.into_iter().try_fold(0_u64, |sum, value| {
        sum.checked_add(value)
            .ok_or_else(|| anyhow!("{label} overflow"))
    })
}

fn serialize_census(report: &JitShapeCensusV3) -> anyhow::Result<Vec<u8>> {
    report.validate()?;
    let mut bytes = serde_json::to_vec(report).context("serialize JIT shape census v3")?;
    bytes.push(b'\n');
    Ok(bytes)
}

pub(crate) fn parse_census_v3(bytes: &[u8]) -> anyhow::Result<JitShapeCensusV3> {
    if bytes.last() != Some(&b'\n') || bytes.iter().filter(|byte| **byte == b'\n').count() != 1 {
        bail!("JIT shape census must be exactly one newline-terminated JSON object");
    }
    let report: JitShapeCensusV3 =
        serde_json::from_slice(&bytes[..bytes.len() - 1]).context("parse JIT shape census v3")?;
    report.validate()?;
    if serialize_census(&report)? != bytes {
        bail!("JIT shape census is not canonical v3 output");
    }
    Ok(report)
}

fn require_distinct<T: PartialEq>(a: &T, b: &T, label: &str) -> anyhow::Result<()> {
    if a == b {
        bail!("comparison {label} must identify distinct captures");
    }
    Ok(())
}

fn validate_comparison_population(
    population: &CensusPopulations,
    label: &str,
) -> anyhow::Result<()> {
    let classified_cpu = population
        .user_cpu
        .checked_add(population.kernel_cpu)
        .and_then(|value| value.checked_add(population.invalid_cpu))
        .with_context(|| format!("comparison census {label} CPU population overflow"))?;
    if classified_cpu != population.all_cpu
        || population.invalid_cpu != 0
        || population.jit_user.checked_add(population.non_jit_user) != Some(population.user_cpu)
        || population.jit_user == 0
        || population.pc_rows == 0
        || population.pc_samples != population.jit_user
        || population.pc_samples < population.pc_rows
    {
        bail!("comparison census {label} populations do not reconcile");
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum ComparisonRowKind {
    Family,
    Word,
    Context,
}

fn validate_comparison_key(key: &ComparisonKey, expected: ComparisonRowKind) -> anyhow::Result<()> {
    match (expected, key) {
        (
            ComparisonRowKind::Family,
            ComparisonKey::Family {
                evidence_class: _,
                family,
            },
        ) => {
            if family.is_empty() {
                bail!("comparison family key is empty");
            }
        }
        (
            ComparisonRowKind::Word,
            ComparisonKey::Word {
                family,
                word,
                evidence_class,
            },
        ) => {
            if family.is_empty() {
                bail!("comparison word family is empty");
            }
            let classification = classify(*word);
            if classification.family != family || classification.evidence_class != *evidence_class {
                bail!("comparison word key disagrees with the current classifier");
            }
        }
        (
            ComparisonRowKind::Context,
            ComparisonKey::Context {
                direction: _,
                first,
                second,
            },
        ) => {
            validate_context_operand(first, "first comparison")?;
            second
                .as_ref()
                .map(|operand| validate_context_operand(operand, "second comparison"))
                .transpose()?;
        }
        _ => bail!("comparison row key kind is in the wrong population"),
    }
    Ok(())
}

fn validate_comparison_rows(
    rows: &[ComparisonRow],
    expected: ComparisonRowKind,
    determinants: &ComparisonDeterminants,
) -> anyhow::Result<()> {
    let mut previous = None;
    for row in rows {
        validate_comparison_key(&row.key, expected)?;
        if previous.as_ref().is_some_and(|key| key >= &row.key) {
            bail!("comparison rows are duplicate or out of order");
        }
        validate_share(
            &row.a,
            determinants.a_populations.jit_user,
            determinants.a_populations.all_cpu,
        )?;
        validate_share(
            &row.b,
            determinants.b_populations.jit_user,
            determinants.b_populations.all_cpu,
        )?;
        if row.a.samples == 0 && row.b.samples == 0 {
            bail!("comparison full-outer-join row is absent from both inputs");
        }
        let drift = absolute_fraction_drift(&row.a.share_of_all_cpu, &row.b.share_of_all_cpu)?;
        if row.absolute_all_cpu_drift != drift {
            bail!("comparison row absolute all-CPU drift is not exact");
        }
        previous = Some(row.key.clone());
    }
    Ok(())
}

fn checked_map_increment<K: Ord>(
    map: &mut BTreeMap<K, u64>,
    key: K,
    samples: u64,
    label: &str,
) -> anyhow::Result<()> {
    checked_increment(map.entry(key).or_default(), samples, label)
}

fn validate_comparison_populations(report: &JitShapeComparisonV1) -> anyhow::Result<()> {
    let mut family_a = BTreeMap::<(EvidenceClass, String), u64>::new();
    let mut family_b = BTreeMap::<(EvidenceClass, String), u64>::new();
    for row in &report.family_rows {
        let ComparisonKey::Family {
            evidence_class,
            family,
        } = &row.key
        else {
            bail!("comparison family row lost its family key");
        };
        family_a.insert((*evidence_class, family.clone()), row.a.samples);
        family_b.insert((*evidence_class, family.clone()), row.b.samples);
    }
    if checked_sum(family_a.values().copied(), "comparison family A total")?
        != report.determinants.a_populations.jit_user
        || checked_sum(family_b.values().copied(), "comparison family B total")?
            != report.determinants.b_populations.jit_user
    {
        bail!("comparison family rows do not reproduce both JIT populations");
    }

    let mut word_a = BTreeMap::<(EvidenceClass, String), u64>::new();
    let mut word_b = BTreeMap::<(EvidenceClass, String), u64>::new();
    let mut expected_context_a = BTreeMap::<ContextAccess, u64>::new();
    let mut expected_context_b = BTreeMap::<ContextAccess, u64>::new();
    for row in &report.word_rows {
        let ComparisonKey::Word {
            family,
            word,
            evidence_class,
        } = &row.key
        else {
            bail!("comparison word row lost its word key");
        };
        checked_map_increment(
            &mut word_a,
            (*evidence_class, family.clone()),
            row.a.samples,
            "comparison word A family total",
        )?;
        checked_map_increment(
            &mut word_b,
            (*evidence_class, family.clone()),
            row.b.samples,
            "comparison word B family total",
        )?;
        let decoded = decode_context(*word);
        match (is_context_family(family), decoded) {
            (true, Some(access)) => {
                checked_map_increment(
                    &mut expected_context_a,
                    access,
                    row.a.samples,
                    "comparison expected context A total",
                )?;
                checked_map_increment(
                    &mut expected_context_b,
                    access,
                    row.b.samples,
                    "comparison expected context B total",
                )?;
            }
            (true, None) => bail!("comparison context word did not decode"),
            (false, Some(_)) => bail!("comparison non-context word decoded as context traffic"),
            (false, None) => {}
        }
    }
    if word_a != family_a || word_b != family_b {
        bail!("comparison word rows do not exactly reproduce family populations");
    }

    let mut actual_context_a = BTreeMap::<ContextAccess, u64>::new();
    let mut actual_context_b = BTreeMap::<ContextAccess, u64>::new();
    for row in &report.context_rows {
        let ComparisonKey::Context {
            direction,
            first,
            second,
        } = &row.key
        else {
            bail!("comparison context row lost its context key");
        };
        let access = ContextAccess {
            direction: *direction,
            first: validate_context_operand(first, "first comparison")?,
            second: second
                .as_ref()
                .map(|operand| validate_context_operand(operand, "second comparison"))
                .transpose()?,
        };
        actual_context_a.insert(access, row.a.samples);
        actual_context_b.insert(access, row.b.samples);
    }
    if actual_context_a != expected_context_a || actual_context_b != expected_context_b {
        bail!("comparison context rows do not reproduce compound word evidence");
    }
    Ok(())
}

fn comparison_determinants(
    a: &JitShapeCensusV3,
    b: &JitShapeCensusV3,
) -> anyhow::Result<ComparisonDeterminants> {
    let determinants = ComparisonDeterminants {
        a_capture_authority: a.capture_authority.clone(),
        b_capture_authority: b.capture_authority.clone(),
        a_census_identity: a.census_identity.clone(),
        b_census_identity: b.census_identity.clone(),
        classifier_schema: a.classifier_schema.clone(),
        a_capture_receipt_sha256: a.capture_receipt_sha256.clone(),
        b_capture_receipt_sha256: b.capture_receipt_sha256.clone(),
        a_raw_trace_sha256: a.raw_trace_sha256.clone(),
        b_raw_trace_sha256: b.raw_trace_sha256.clone(),
        a_snapshot_manifest_sha256: a.snapshot_manifest_sha256.clone(),
        b_snapshot_manifest_sha256: b.snapshot_manifest_sha256.clone(),
        a_populations: a.populations.clone(),
        b_populations: b.populations.clone(),
    };
    determinants.validate()?;
    Ok(determinants)
}

fn zero_share(populations: &CensusPopulations) -> CensusShare {
    census_share(0, populations.jit_user, populations.all_cpu)
}

fn absolute_fraction_drift(
    a: &CensusFraction,
    b: &CensusFraction,
) -> anyhow::Result<ComparisonFraction> {
    if a.denominator == 0 || b.denominator == 0 {
        bail!("comparison share denominator is zero");
    }
    let a_scaled = u128::from(a.numerator)
        .checked_mul(u128::from(b.denominator))
        .context("comparison A share cross multiplication overflow")?;
    let b_scaled = u128::from(b.numerator)
        .checked_mul(u128::from(a.denominator))
        .context("comparison B share cross multiplication overflow")?;
    let denominator = u128::from(a.denominator)
        .checked_mul(u128::from(b.denominator))
        .context("comparison drift denominator overflow")?;
    Ok(ComparisonFraction {
        numerator: a_scaled.abs_diff(b_scaled),
        denominator,
    })
}

fn share_at_least_ten_percent(share: &CensusFraction) -> anyhow::Result<bool> {
    let numerator = u128::from(share.numerator)
        .checked_mul(100)
        .context("comparison ten-percent numerator overflow")?;
    let denominator = u128::from(share.denominator)
        .checked_mul(10)
        .context("comparison ten-percent denominator overflow")?;
    Ok(numerator >= denominator)
}

fn mechanical_crossing_gate(
    a: &CensusFraction,
    b: &CensusFraction,
) -> anyhow::Result<(bool, ComparisonFraction)> {
    let drift = absolute_fraction_drift(a, b)?;
    let drift_percent = drift
        .numerator
        .checked_mul(100)
        .context("comparison drift percentage numerator overflow")?;
    let five_percent = drift
        .denominator
        .checked_mul(5)
        .context("comparison five-percentage-point denominator overflow")?;
    let crosses = share_at_least_ten_percent(a)?
        && share_at_least_ten_percent(b)?
        && drift_percent <= five_percent;
    Ok((crosses, drift))
}

fn minimum_fraction(a: &CensusFraction, b: &CensusFraction) -> anyhow::Result<CensusFraction> {
    if compare_fraction(a, b)?.is_le() {
        Ok(a.clone())
    } else {
        Ok(b.clone())
    }
}

fn compare_fraction(a: &CensusFraction, b: &CensusFraction) -> anyhow::Result<std::cmp::Ordering> {
    let a_scaled = u128::from(a.numerator)
        .checked_mul(u128::from(b.denominator))
        .context("comparison fraction A cross multiplication overflow")?;
    let b_scaled = u128::from(b.numerator)
        .checked_mul(u128::from(a.denominator))
        .context("comparison fraction B cross multiplication overflow")?;
    Ok(a_scaled.cmp(&b_scaled))
}

fn join_comparison_rows(
    a: BTreeMap<ComparisonKey, CensusShare>,
    b: BTreeMap<ComparisonKey, CensusShare>,
    a_populations: &CensusPopulations,
    b_populations: &CensusPopulations,
) -> anyhow::Result<Vec<ComparisonRow>> {
    let mut keys = a.keys().chain(b.keys()).cloned().collect::<Vec<_>>();
    keys.sort();
    keys.dedup();
    keys.into_iter()
        .map(|key| {
            let a_share = a
                .get(&key)
                .cloned()
                .unwrap_or_else(|| zero_share(a_populations));
            let b_share = b
                .get(&key)
                .cloned()
                .unwrap_or_else(|| zero_share(b_populations));
            let absolute_all_cpu_drift =
                absolute_fraction_drift(&a_share.share_of_all_cpu, &b_share.share_of_all_cpu)?;
            Ok(ComparisonRow {
                key,
                a: a_share,
                b: b_share,
                absolute_all_cpu_drift,
            })
        })
        .collect()
}

fn comparison_family_map(census: &JitShapeCensusV3) -> BTreeMap<ComparisonKey, CensusShare> {
    census
        .families
        .iter()
        .map(|row| {
            (
                ComparisonKey::Family {
                    evidence_class: row.evidence_class,
                    family: row.family.clone(),
                },
                row.share.clone(),
            )
        })
        .collect()
}

fn comparison_word_map(census: &JitShapeCensusV3) -> BTreeMap<ComparisonKey, CensusShare> {
    census
        .words
        .iter()
        .map(|row| {
            (
                ComparisonKey::Word {
                    family: row.family.clone(),
                    word: row.word,
                    evidence_class: row.evidence_class,
                },
                row.share.clone(),
            )
        })
        .collect()
}

fn comparison_context_map(census: &JitShapeCensusV3) -> BTreeMap<ComparisonKey, CensusShare> {
    census
        .contexts
        .iter()
        .map(|row| {
            (
                ComparisonKey::Context {
                    direction: row.direction,
                    first: row.first.clone(),
                    second: row.second.clone(),
                },
                row.share.clone(),
            )
        })
        .collect()
}

fn mechanical_crossings(
    rows: impl IntoIterator<Item = ComparisonRow>,
) -> anyhow::Result<Vec<MechanicalCrossing>> {
    let mut crossings = Vec::new();
    for row in rows {
        let (crosses, drift) =
            mechanical_crossing_gate(&row.a.share_of_all_cpu, &row.b.share_of_all_cpu)?;
        if crosses {
            crossings.push(MechanicalCrossing {
                key: row.key,
                minimum_all_cpu_share: minimum_fraction(
                    &row.a.share_of_all_cpu,
                    &row.b.share_of_all_cpu,
                )?,
                a: row.a,
                b: row.b,
                absolute_all_cpu_drift: drift,
            });
        }
    }
    for index in 1..crossings.len() {
        let mut current = index;
        while current > 0 {
            let previous = &crossings[current - 1];
            let candidate = &crossings[current];
            let share_order = compare_fraction(
                &previous.minimum_all_cpu_share,
                &candidate.minimum_all_cpu_share,
            )?;
            let is_ordered =
                share_order.is_gt() || (share_order.is_eq() && previous.key < candidate.key);
            if is_ordered {
                break;
            }
            crossings.swap(current - 1, current);
            current -= 1;
        }
    }
    Ok(crossings)
}

fn build_comparison_from_bytes(
    a_bytes: &[u8],
    b_bytes: &[u8],
) -> anyhow::Result<JitShapeComparisonV1> {
    if a_bytes == b_bytes {
        bail!("JIT shape comparison inputs are byte-identical");
    }
    let a = parse_census_v3(a_bytes).context("parse strict canonical census A")?;
    let b = parse_census_v3(b_bytes).context("parse strict canonical census B")?;
    let determinants = comparison_determinants(&a, &b)?;
    let a_sha256 = format!("{:x}", Sha256::digest(a_bytes));
    let b_sha256 = format!("{:x}", Sha256::digest(b_bytes));
    require_distinct(&a_sha256, &b_sha256, "census hashes")?;
    let family_rows = join_comparison_rows(
        comparison_family_map(&a),
        comparison_family_map(&b),
        &a.populations,
        &b.populations,
    )?;
    let word_rows = join_comparison_rows(
        comparison_word_map(&a),
        comparison_word_map(&b),
        &a.populations,
        &b.populations,
    )?;
    let context_rows = join_comparison_rows(
        comparison_context_map(&a),
        comparison_context_map(&b),
        &a.populations,
        &b.populations,
    )?;
    let mechanical_crossings = mechanical_crossings(
        family_rows
            .iter()
            .chain(&word_rows)
            .chain(&context_rows)
            .cloned(),
    )?;
    let report = JitShapeComparisonV1 {
        schema: COMPARISON_SCHEMA.to_owned(),
        a_sha256,
        b_sha256,
        determinants,
        family_rows,
        word_rows,
        context_rows,
        mechanical_crossings,
    };
    report.validate()?;
    Ok(report)
}

fn serialize_comparison(report: &JitShapeComparisonV1) -> anyhow::Result<Vec<u8>> {
    report.validate()?;
    let mut bytes = serde_json::to_vec(report).context("serialize JIT shape comparison v1")?;
    bytes.push(b'\n');
    Ok(bytes)
}

pub(crate) fn parse_comparison_v1(bytes: &[u8]) -> anyhow::Result<JitShapeComparisonV1> {
    if bytes.last() != Some(&b'\n') || bytes.iter().filter(|byte| **byte == b'\n').count() != 1 {
        bail!("JIT shape comparison must be exactly one newline-terminated JSON object");
    }
    let report: JitShapeComparisonV1 = serde_json::from_slice(&bytes[..bytes.len() - 1])
        .context("parse JIT shape comparison v1")?;
    report.validate()?;
    if serialize_comparison(&report)? != bytes {
        bail!("JIT shape comparison is not canonical v1 output");
    }
    Ok(report)
}

fn publish_noclobber(
    bytes: &[u8],
    output_path: Option<&Path>,
    stdout: &mut impl Write,
    artifact: &str,
) -> anyhow::Result<()> {
    let Some(path) = output_path else {
        stdout
            .write_all(bytes)
            .with_context(|| format!("write {artifact} to stdout"))?;
        stdout
            .flush()
            .with_context(|| format!("flush {artifact} stdout"))?;
        return Ok(());
    };

    let parent = path
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)
        .with_context(|| format!("create {artifact} output directory {}", parent.display()))?;
    let mut temporary = NamedTempFile::new_in(parent)
        .with_context(|| format!("create temporary {artifact} in {}", parent.display()))?;
    {
        let mut writer = BufWriter::new(temporary.as_file_mut());
        writer
            .write_all(bytes)
            .with_context(|| format!("write {artifact} artifact"))?;
        writer
            .flush()
            .with_context(|| format!("flush {artifact} artifact"))?;
    }
    temporary
        .as_file()
        .sync_all()
        .with_context(|| format!("sync {artifact} artifact"))?;
    temporary.persist_noclobber(path).map_err(|error| {
        if error.error.kind() == std::io::ErrorKind::AlreadyExists {
            anyhow!("{artifact} output already exists: {}", path.display())
        } else {
            anyhow!(
                "publish {artifact} {} without clobbering: {}",
                path.display(),
                error.error
            )
        }
    })?;
    Ok(())
}

fn publish_comparison(
    report: &JitShapeComparisonV1,
    output_path: Option<&Path>,
    stdout: &mut impl Write,
) -> anyhow::Result<()> {
    let bytes = serialize_comparison(report)?;
    parse_comparison_v1(&bytes).context("self-validate published JIT shape comparison")?;
    publish_noclobber(&bytes, output_path, stdout, "JIT shape comparison v1")
}

fn publish_census(
    report: &JitShapeCensusV3,
    output_path: Option<&Path>,
    stdout: &mut impl Write,
) -> anyhow::Result<()> {
    let bytes = serialize_census(report)?;
    parse_census_v3(&bytes).context("self-validate published JIT shape census")?;
    publish_noclobber(&bytes, output_path, stdout, "JIT shape census v3")
}

pub(crate) fn run_jit_shape_compare(
    a_path: &Path,
    b_path: &Path,
    output_path: Option<&Path>,
) -> anyhow::Result<()> {
    let executable = std::env::current_exe().context("resolve running comparison executable")?;
    let stdout = std::io::stdout();
    let mut stdout = stdout.lock();
    run_jit_shape_compare_with_identity_capture(a_path, b_path, output_path, &mut stdout, || {
        CaptureIdentity::capture(&executable)
    })
}

fn run_jit_shape_compare_with_identity_capture(
    a_path: &Path,
    b_path: &Path,
    output_path: Option<&Path>,
    stdout: &mut impl Write,
    mut capture_identity: impl FnMut() -> anyhow::Result<CaptureIdentity>,
) -> anyhow::Result<()> {
    if a_path == b_path {
        bail!("JIT shape comparison requires two distinct census files");
    }
    let before = capture_identity().context("capture pre-comparison source/binary identity")?;
    let a_bytes = fs::read(a_path)
        .with_context(|| format!("read JIT shape census A {}", a_path.display()))?;
    let b_bytes = fs::read(b_path)
        .with_context(|| format!("read JIT shape census B {}", b_path.display()))?;
    let report = build_comparison_from_bytes(&a_bytes, &b_bytes)?;
    before
        .require_exact_match(&report.determinants.a_census_identity)
        .context("comparison executor does not match census A classifier identity")?;
    before
        .require_exact_match(&report.determinants.b_census_identity)
        .context("comparison executor does not match census B classifier identity")?;
    let after = capture_identity().context("capture post-comparison source/binary identity")?;
    before
        .require_exact_match(&after)
        .context("comparison source/binary identity drift")?;
    publish_comparison(&report, output_path, stdout)
}

fn run_jit_shape_census_with_identity_capture(
    trace_path: &Path,
    capture_path: &Path,
    snapshot_directory: &Path,
    output_path: Option<&Path>,
    stdout: &mut impl Write,
    mut capture_identity: impl FnMut() -> anyhow::Result<CaptureIdentity>,
) -> anyhow::Result<()> {
    let before = capture_identity().context("capture pre-census source/binary identity")?;
    let raw_bytes = fs::read(trace_path)
        .with_context(|| format!("read native-shape trace {}", trace_path.display()))?;
    let receipt_bytes = fs::read(capture_path).with_context(|| {
        format!(
            "read native-shape capture receipt {}",
            capture_path.display()
        )
    })?;
    let report =
        build_authenticated_census(&raw_bytes, &receipt_bytes, snapshot_directory, &before)?;
    let after = capture_identity().context("capture post-census source/binary identity")?;
    before
        .require_exact_match(&after)
        .context("census source/binary identity drift")?;
    publish_census(&report, output_path, stdout)
}

fn context_semantic_label(slot: i64) -> &'static str {
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
    use crate::jit_shape_snapshot::{SnapshotSet, write_v4_test_snapshot};
    use crate::native_shape_profile::{
        CAPTURE_SCHEMA, CaptureIdentity, CaptureOutcome, NativeShapeAuthority,
        NativeShapeCaptureReceipt, NativeShapeCounts, NativeShapeDrops, NativeShapeLifecycle,
        argv_sha256,
    };

    struct CensusFixture {
        _root: tempfile::TempDir,
        raw: Vec<u8>,
        receipt: Vec<u8>,
        snapshots: std::path::PathBuf,
        identity: CaptureIdentity,
    }

    impl CensusFixture {
        fn new() -> Self {
            let root = tempfile::tempdir().expect("census fixture root");
            let snapshots = root.path().join("snapshots");
            std::fs::create_dir(&snapshots).expect("create census snapshots");
            write_v4_test_snapshot(
                &snapshots,
                "10-1",
                10,
                0x1000,
                &[0xf942_3791, 0xa901_0791, 0x1400_0000, 0xf940_0240],
            );
            let identity = fixture_census_identity();
            let authority = fixture_census_authority();
            let raw = format!(
                "{}\nNSHAPE2|exit|pid=10|reason=1\nNSHAPE2|section=mode\nNSHAPE2|mode|kind=all|count=10\nNSHAPE2|mode|kind=user|count=8\nNSHAPE2|mode|kind=kernel|count=2\nNSHAPE2|mode|kind=invalid|count=0\nNSHAPE2|section=region\nNSHAPE2|region|kind=jit|count=4\nNSHAPE2|region|kind=non-jit|count=4\nNSHAPE2|section=pc\nNSHAPE2|pc|pid=10|pc=0x1000|count=1\nNSHAPE2|pc|pid=10|pc=0x1004|count=1\nNSHAPE2|pc|pid=10|pc=0x1008|count=1\nNSHAPE2|pc|pid=10|pc=0x100c|count=1\nNSHAPE2|complete|bounded=0|target_completed=1|target_exit_reason=1|target_pid=10|admitted=1|exited=1|live_at_end=0|probe_errors=0\n",
                authority.header_record().expect("fixture authority header")
            )
            .into_bytes();
            let manifest = SnapshotSet::load(&snapshots)
                .expect("load fixture snapshots")
                .manifest()
                .clone();
            let receipt = NativeShapeCaptureReceipt {
                schema: CAPTURE_SCHEMA.to_owned(),
                outcome: CaptureOutcome::Accepted,
                evidence_errors: Vec::new(),
                authority_sha256: Some(authority.sha256().expect("fixture authority digest")),
                authority: Some(authority),
                raw_trace_sha256: Some(format!("{:x}", Sha256::digest(&raw))),
                snapshot_manifest: Some(manifest),
                counts: Some(NativeShapeCounts {
                    all_cpu: 10,
                    user_cpu: 8,
                    kernel_cpu: 2,
                    invalid_cpu: 0,
                    jit_user: 4,
                    non_jit_user: 4,
                    pc_rows: 4,
                    pc_samples: 4,
                }),
                lifecycle: Some(NativeShapeLifecycle {
                    bounded: false,
                    target_completed: true,
                    target_exit_reason: 1,
                    target_pid: 10,
                    admitted: 1,
                    exited: 1,
                    live_at_end: 0,
                    probe_errors: 0,
                }),
                drops: NativeShapeDrops::default(),
            };
            let mut receipt = serde_json::to_vec(&receipt).expect("serialize fixture receipt");
            receipt.push(b'\n');
            Self {
                _root: root,
                raw,
                receipt,
                snapshots,
                identity,
            }
        }

        fn build(&self) -> anyhow::Result<JitShapeCensusV3> {
            build_authenticated_census(&self.raw, &self.receipt, &self.snapshots, &self.identity)
        }
    }

    fn fixture_census_identity() -> CaptureIdentity {
        CaptureIdentity {
            git_head: "0123456789abcdef0123456789abcdef01234567".to_owned(),
            git_dirty: false,
            executable_sha256: "5".repeat(64),
            host: "census-host".to_owned(),
            host_arch: "aarch64".to_owned(),
            os_build: "26A5388g".to_owned(),
        }
    }

    fn fixture_census_authority() -> NativeShapeAuthority {
        let target_argv = vec![
            "run".to_owned(),
            "--exec-backend".to_owned(),
            "native".to_owned(),
            "docker.io/library/ubuntu@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
            "/bin/true".to_owned(),
        ];
        NativeShapeAuthority {
            schema: "carrick.native-shape-authority.v1".to_owned(),
            profile: "native-shape".to_owned(),
            raw_schema: "carrick.native-shape.raw.v2".to_owned(),
            git_head: "fedcba9876543210fedcba9876543210fedcba98".to_owned(),
            git_dirty: false,
            executable_sha256: "1".repeat(64),
            host: "capture-host".to_owned(),
            host_arch: "aarch64".to_owned(),
            os_build: "26A5388g".to_owned(),
            image: "docker.io/library/ubuntu@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
            target_argv_sha256: argv_sha256(&target_argv).expect("fixture argv digest"),
            target_argv,
            run_id: "native-shape-census-fixture".to_owned(),
            program_template_sha256: "2".repeat(64),
            birth_qualification_sha256: "3".repeat(64),
            terminal_qualification_sha256: "4".repeat(64),
            sampling_hz: 997,
        }
    }

    fn decode_fixture_receipt(bytes: &[u8]) -> NativeShapeCaptureReceipt {
        serde_json::from_slice(bytes).expect("decode fixture receipt")
    }

    fn encode_fixture_receipt(receipt: &NativeShapeCaptureReceipt) -> Vec<u8> {
        let mut bytes = serde_json::to_vec(receipt).expect("encode fixture receipt");
        bytes.push(b'\n');
        bytes
    }

    fn census_fixture_with_words(words: &[u32]) -> CensusFixture {
        let root = tempfile::tempdir().expect("census fixture root");
        let snapshots = root.path().join("snapshots");
        std::fs::create_dir(&snapshots).expect("create census snapshots");
        write_v4_test_snapshot(&snapshots, "10-1", 10, 0x1000, words);
        let identity = fixture_census_identity();
        let authority = fixture_census_authority();
        let samples = u64::try_from(words.len()).expect("fixture word population fits u64");
        let pc_rows = words
            .iter()
            .enumerate()
            .map(|(index, _)| {
                format!(
                    "NSHAPE2|pc|pid=10|pc={:#x}|count=1",
                    0x1000_u64 + u64::try_from(index).unwrap() * 4
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        let raw = format!(
            "{}\nNSHAPE2|exit|pid=10|reason=1\nNSHAPE2|section=mode\nNSHAPE2|mode|kind=all|count={samples}\nNSHAPE2|mode|kind=user|count={samples}\nNSHAPE2|mode|kind=kernel|count=0\nNSHAPE2|mode|kind=invalid|count=0\nNSHAPE2|section=region\nNSHAPE2|region|kind=jit|count={samples}\nNSHAPE2|region|kind=non-jit|count=0\nNSHAPE2|section=pc\n{pc_rows}\nNSHAPE2|complete|bounded=0|target_completed=1|target_exit_reason=1|target_pid=10|admitted=1|exited=1|live_at_end=0|probe_errors=0\n",
            authority.header_record().expect("fixture authority header")
        )
        .into_bytes();
        let manifest = SnapshotSet::load(&snapshots)
            .expect("load fixture snapshots")
            .manifest()
            .clone();
        let receipt = NativeShapeCaptureReceipt {
            schema: CAPTURE_SCHEMA.to_owned(),
            outcome: CaptureOutcome::Accepted,
            evidence_errors: Vec::new(),
            authority_sha256: Some(authority.sha256().expect("fixture authority digest")),
            authority: Some(authority),
            raw_trace_sha256: Some(format!("{:x}", Sha256::digest(&raw))),
            snapshot_manifest: Some(manifest),
            counts: Some(NativeShapeCounts {
                all_cpu: samples,
                user_cpu: samples,
                kernel_cpu: 0,
                invalid_cpu: 0,
                jit_user: samples,
                non_jit_user: 0,
                pc_rows: samples,
                pc_samples: samples,
            }),
            lifecycle: Some(NativeShapeLifecycle {
                bounded: false,
                target_completed: true,
                target_exit_reason: 1,
                target_pid: 10,
                admitted: 1,
                exited: 1,
                live_at_end: 0,
                probe_errors: 0,
            }),
            drops: NativeShapeDrops::default(),
        };
        CensusFixture {
            _root: root,
            raw,
            receipt: encode_fixture_receipt(&receipt),
            snapshots,
            identity,
        }
    }

    #[test]
    fn jit_shape_inserted_floor_excludes_guest_identical_exact_encodings() {
        let fixture = census_fixture_with_words(&[
            0xf942_3791, // source-exclusive x28-based context load
            0xc8df_fe73, // guest-identical LDAR
            0xb257_0013, // guest-identical ORR immediate
            0xd51b_4211, // guest-identical MSR NZCV
            0xd53b_4211, // guest-identical MRS NZCV
            0xd280_0011, // guest-identical x17 materialization
            0x1400_0000, // guest descriptive
        ]);
        let report = fixture.build().expect("build conservative floor fixture");

        assert_eq!(report.words.len(), 7, "exact rows must remain complete");
        assert_eq!(
            report
                .families
                .iter()
                .filter(|row| matches!(
                    row.family.as_str(),
                    "guard-ldar" | "bias-orr" | "nzcv-msr" | "nzcv-mrs" | "x17-materialize"
                ))
                .map(|row| row.share.samples)
                .sum::<u64>(),
            5,
            "all guest-identical exact families must remain visible",
        );
        assert_eq!(
            report.inserted_exact_floor.samples, 1,
            "the floor may contain only the source-exclusive context load",
        );
        assert_eq!(
            serde_json::to_string(&EvidenceClass::ExactAmbiguous).unwrap(),
            "\"exact-ambiguous\"",
        );
    }

    #[test]
    fn jit_shape_rejects_non_aarch64_census_identity() {
        let mut fixture = CensusFixture::new();
        fixture.identity.host_arch = "x86_64".to_owned();
        let error = fixture
            .build()
            .expect_err("non-AArch64 classifier identity must fail closed");
        assert!(format!("{error:#}").contains("aarch64"), "{error:#}");
    }

    #[test]
    fn jit_shape_v3_report_has_complete_integer_populations_and_ordered_rows() {
        let fixture = CensusFixture::new();
        let report = fixture.build().expect("build authenticated v3 census");

        assert_eq!(report.schema, "carrick.jit-shape-census.v3");
        assert_eq!(
            report.classifier_schema,
            "carrick.jit-shape-classifier.aarch64.v3"
        );
        assert_eq!(report.populations.all_cpu, 10);
        assert_eq!(report.populations.jit_user, 4);
        assert_eq!(report.coverage.resolved_samples, 4);
        assert_eq!(report.coverage.own_samples, 4);
        assert_eq!(report.coverage.inherited_samples, 0);
        assert_eq!(report.coverage.missing_samples, 0);
        assert_eq!(report.inserted_exact_floor.samples, 3);
        assert_eq!(
            report.inserted_exact_floor.share_of_jit,
            CensusFraction {
                numerator: 3,
                denominator: 4,
            }
        );
        assert_eq!(
            report.inserted_exact_floor.share_of_all_cpu,
            CensusFraction {
                numerator: 3,
                denominator: 10,
            }
        );
        assert_eq!(
            report
                .families
                .iter()
                .map(|row| (row.evidence_class, row.family.as_str()))
                .collect::<Vec<_>>(),
            vec![
                (EvidenceClass::InsertedExact, "ctx-load64"),
                (EvidenceClass::InsertedExact, "ctx-pair"),
                (EvidenceClass::InsertedExact, "x18-based-ldst"),
                (EvidenceClass::GuestDescriptive, "b/bl"),
            ]
        );
        assert_eq!(report.words.len(), 4);
        assert_eq!(
            report
                .words
                .iter()
                .map(|row| (row.family.as_str(), row.word))
                .collect::<Vec<_>>(),
            vec![
                ("b/bl", 0x1400_0000),
                ("ctx-load64", 0xf942_3791),
                ("ctx-pair", 0xa901_0791),
                ("x18-based-ldst", 0xf940_0240),
            ]
        );
        assert_eq!(
            report
                .contexts
                .iter()
                .map(|row| {
                    (
                        row.direction,
                        row.first.slot,
                        row.first.physical_register,
                        row.second
                            .as_ref()
                            .map(|operand| (operand.slot, operand.physical_register)),
                        row.share.samples,
                    )
                })
                .collect::<Vec<_>>(),
            vec![
                (Direction::Load, 1128, 17, None, 1),
                (Direction::Store, 16, 17, Some((24, 1)), 1),
            ]
        );
    }

    #[test]
    fn jit_shape_v3_publication_is_one_deterministic_line_and_never_clobbers() {
        let fixture = CensusFixture::new();
        let report = fixture.build().expect("build authenticated v3 census");
        let mut first = Vec::new();
        let mut second = Vec::new();
        publish_census(&report, None, &mut first).expect("publish first census to stdout sink");
        publish_census(&report, None, &mut second).expect("publish second census to stdout sink");
        assert_eq!(first, second);
        assert_eq!(first.last(), Some(&b'\n'));
        assert_eq!(first.iter().filter(|byte| **byte == b'\n').count(), 1);

        let output = fixture._root.path().join("census.json");
        let mut unused_stdout = Vec::new();
        publish_census(&report, Some(&output), &mut unused_stdout)
            .expect("publish census artifact");
        assert!(
            unused_stdout.is_empty(),
            "file output emitted a second format"
        );
        assert_eq!(std::fs::read(&output).expect("read census artifact"), first);
        let error = publish_census(&report, Some(&output), &mut unused_stdout)
            .expect_err("census publication must not clobber");
        assert!(format!("{error:#}").contains("already exists"));
        assert_eq!(
            std::fs::read(&output).expect("reread census artifact"),
            first
        );

        let mut value: serde_json::Value =
            serde_json::from_slice(&first).expect("parse census JSON");
        value["unknown"] = true.into();
        assert!(serde_json::from_value::<JitShapeCensusV3>(value).is_err());
    }

    #[test]
    fn jit_shape_runner_captures_identity_before_and_after_analysis() {
        let fixture = CensusFixture::new();
        let raw_path = fixture._root.path().join("raw.trace");
        let receipt_path = fixture._root.path().join("capture.jsonl");
        std::fs::write(&raw_path, &fixture.raw).expect("write runner raw fixture");
        std::fs::write(&receipt_path, &fixture.receipt).expect("write runner receipt fixture");
        let mut captures = 0_u8;
        let mut stdout = Vec::new();
        run_jit_shape_census_with_identity_capture(
            &raw_path,
            &receipt_path,
            &fixture.snapshots,
            None,
            &mut stdout,
            || {
                captures += 1;
                Ok(fixture.identity.clone())
            },
        )
        .expect("run census with stable identity");
        assert_eq!(captures, 2);
        assert_eq!(stdout, serialize_census(&fixture.build().unwrap()).unwrap());
    }

    #[test]
    fn jit_shape_rejects_receipt_schema_outcome_and_noncanonical_substitution() {
        let fixture = CensusFixture::new();
        for receipt in [
            b"{\"schema\":\"carrick.native-shape-capture.v0\"}\n".to_vec(),
            b"{\"schema\":\"carrick.jit-shape-census.v1\"}\n".to_vec(),
            {
                let mut bytes = fixture.receipt.clone();
                bytes.insert(bytes.len() - 1, b' ');
                bytes
            },
            {
                let mut receipt = decode_fixture_receipt(&fixture.receipt);
                receipt.outcome = CaptureOutcome::Rejected;
                receipt.evidence_errors = vec!["substituted".to_owned()];
                receipt.authority = None;
                receipt.authority_sha256 = None;
                receipt.raw_trace_sha256 = None;
                receipt.snapshot_manifest = None;
                receipt.counts = None;
                receipt.lifecycle = None;
                encode_fixture_receipt(&receipt)
            },
        ] {
            assert!(
                build_authenticated_census(
                    &fixture.raw,
                    &receipt,
                    &fixture.snapshots,
                    &fixture.identity,
                )
                .is_err(),
                "accepted substituted receipt: {}",
                String::from_utf8_lossy(&receipt)
            );
        }
    }

    #[test]
    fn jit_shape_rejects_raw_and_capture_authority_substitution() {
        let mut raw_fixture = CensusFixture::new();
        raw_fixture.raw[0] = b'X';
        assert!(
            raw_fixture.build().is_err(),
            "accepted substituted raw bytes"
        );

        let mut shape1_fixture = CensusFixture::new();
        shape1_fixture.raw = b"SHAPE1|samples=1\n".to_vec();
        let mut receipt = decode_fixture_receipt(&shape1_fixture.receipt);
        receipt.raw_trace_sha256 = Some(format!("{:x}", Sha256::digest(&shape1_fixture.raw)));
        shape1_fixture.receipt = encode_fixture_receipt(&receipt);
        let error = shape1_fixture.build().expect_err("SHAPE1 must be rejected");
        assert!(format!("{error:#}").contains("NSHAPE2"), "{error:#}");

        let mut authority_fixture = CensusFixture::new();
        let mut receipt = decode_fixture_receipt(&authority_fixture.receipt);
        receipt.authority.as_mut().unwrap().run_id = "substituted-run".to_owned();
        receipt.authority_sha256 = Some(receipt.authority.as_ref().unwrap().sha256().unwrap());
        authority_fixture.receipt = encode_fixture_receipt(&receipt);
        let error = authority_fixture
            .build()
            .expect_err("capture authority substitution must be rejected");
        assert!(format!("{error:#}").contains("header"), "{error:#}");
    }

    #[test]
    fn jit_shape_rejects_snapshot_payload_metadata_and_manifest_substitution() {
        let payload_fixture = CensusFixture::new();
        std::fs::write(payload_fixture.snapshots.join("10-1.bin"), [0_u8; 16])
            .expect("substitute snapshot payload");
        assert!(payload_fixture.build().is_err());

        let metadata_fixture = CensusFixture::new();
        let metadata_path = metadata_fixture.snapshots.join("10-1.json");
        let mut metadata: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&metadata_path).expect("read snapshot metadata"))
                .expect("parse snapshot metadata");
        metadata["substituted"] = true.into();
        std::fs::write(&metadata_path, serde_json::to_vec(&metadata).unwrap())
            .expect("substitute snapshot metadata");
        assert!(metadata_fixture.build().is_err());

        let mut manifest_fixture = CensusFixture::new();
        let mut receipt = decode_fixture_receipt(&manifest_fixture.receipt);
        receipt.snapshot_manifest.as_mut().unwrap().sha256 = "9".repeat(64);
        manifest_fixture.receipt = encode_fixture_receipt(&receipt);
        let error = manifest_fixture
            .build()
            .expect_err("snapshot manifest substitution must be rejected");
        assert!(format!("{error:#}").contains("manifest"), "{error:#}");

        let mut counter_fixture = CensusFixture::new();
        let mut receipt = decode_fixture_receipt(&counter_fixture.receipt);
        receipt.snapshot_manifest.as_mut().unwrap().pairs += 1;
        counter_fixture.receipt = encode_fixture_receipt(&receipt);
        assert!(counter_fixture.build().is_err());
    }

    #[test]
    fn jit_shape_recomputes_counts_and_repeats_every_pc_resolution() {
        let mut count_fixture = CensusFixture::new();
        let mut receipt = decode_fixture_receipt(&count_fixture.receipt);
        let counts = receipt.counts.as_mut().unwrap();
        counts.all_cpu += 1;
        counts.kernel_cpu += 1;
        count_fixture.receipt = encode_fixture_receipt(&receipt);
        let error = count_fixture
            .build()
            .expect_err("receipt count substitution must be rejected");
        assert!(format!("{error:#}").contains("populations"), "{error:#}");

        let mut pc_fixture = CensusFixture::new();
        let raw = String::from_utf8(pc_fixture.raw.clone())
            .unwrap()
            .replace("pc=0x100c", "pc=0x2000");
        pc_fixture.raw = raw.into_bytes();
        let mut receipt = decode_fixture_receipt(&pc_fixture.receipt);
        receipt.raw_trace_sha256 = Some(format!("{:x}", Sha256::digest(&pc_fixture.raw)));
        pc_fixture.receipt = encode_fixture_receipt(&receipt);
        let error = pc_fixture
            .build()
            .expect_err("unresolved PC substitution must be rejected");
        assert!(format!("{error:#}").contains("resolve"), "{error:#}");
    }

    #[test]
    fn jit_shape_rejects_dirty_or_drifting_census_source_and_binary_identity() {
        let mut dirty = CensusFixture::new();
        dirty.identity.git_dirty = true;
        assert!(dirty.build().is_err());

        for mutate_after in [
            |identity: &mut CaptureIdentity| identity.git_head = "f".repeat(40),
            |identity: &mut CaptureIdentity| identity.executable_sha256 = "e".repeat(64),
        ] {
            let fixture = CensusFixture::new();
            let raw_path = fixture._root.path().join("raw.trace");
            let receipt_path = fixture._root.path().join("capture.jsonl");
            std::fs::write(&raw_path, &fixture.raw).unwrap();
            std::fs::write(&receipt_path, &fixture.receipt).unwrap();
            let mut calls = 0_u8;
            let error = run_jit_shape_census_with_identity_capture(
                &raw_path,
                &receipt_path,
                &fixture.snapshots,
                None,
                &mut Vec::new(),
                || {
                    calls += 1;
                    let mut identity = fixture.identity.clone();
                    if calls == 2 {
                        mutate_after(&mut identity);
                    }
                    Ok(identity)
                },
            )
            .expect_err("census identity drift must be rejected");
            assert!(format!("{error:#}").contains("identity drift"), "{error:#}");
        }
    }

    #[test]
    fn jit_shape_checked_arithmetic_rejects_overflow() {
        assert!(checked_sum([u64::MAX, 1], "fixture").is_err());
    }

    #[test]
    fn jit_shape_v3_validator_rejects_population_row_and_share_mutations() {
        type Mutation = fn(&mut JitShapeCensusV3);
        let mutations: &[(&str, Mutation)] = &[
            ("schema", |report| {
                report.schema = "carrick.jit-shape-census.v1".into()
            }),
            ("classifier", |report| {
                report.classifier_schema = "old".into()
            }),
            ("hash", |report| report.raw_trace_sha256 = "0".into()),
            ("population", |report| report.populations.all_cpu += 1),
            ("coverage", |report| report.coverage.own_samples += 1),
            ("family share", |report| {
                report.families[0].share.share_of_jit.numerator += 1
            }),
            ("family order", |report| report.families.swap(0, 1)),
            ("family duplicate", |report| {
                report.families.push(report.families[0].clone())
            }),
            ("word missing", |report| {
                report.words.pop();
            }),
            ("word family", |report| {
                report.words[0].family = "other".into()
            }),
            ("word order", |report| report.words.swap(0, 1)),
            ("context missing", |report| {
                report.contexts.pop();
            }),
            ("context duplicate", |report| {
                report.contexts.push(report.contexts[0].clone())
            }),
            ("context redistributed", |report| {
                report.contexts[0].first.slot = 1120;
                report.contexts[0].first.semantic_label = context_semantic_label(1120).to_owned();
            }),
            ("context second operand redistributed", |report| {
                let second = report.contexts[1]
                    .second
                    .as_mut()
                    .expect("fixture pair context row");
                second.physical_register = 2;
            }),
            ("inserted floor", |report| {
                report.inserted_exact_floor.samples += 1
            }),
        ];
        for (name, mutate) in mutations {
            let fixture = CensusFixture::new();
            let mut report = fixture.build().expect("valid report fixture");
            mutate(&mut report);
            assert!(report.validate().is_err(), "accepted {name} mutation");
        }
    }

    #[test]
    fn jit_shape_v3_strict_reader_requires_canonical_current_report() {
        let fixture = CensusFixture::new();
        let report = fixture.build().expect("valid report fixture");
        let bytes = serialize_census(&report).expect("serialize valid report fixture");
        assert_eq!(parse_census_v3(&bytes).unwrap(), report);

        let mut noncanonical = bytes.clone();
        noncanonical.insert(noncanonical.len() - 1, b' ');
        assert!(parse_census_v3(&noncanonical).is_err());

        let old = b"{\"schema\":\"carrick.jit-shape-census.v1\"}\n";
        assert!(parse_census_v3(old).is_err());
    }

    #[test]
    fn jit_shape_v3_rejects_prior_census_and_classifier_schemas() {
        let fixture = CensusFixture::new();
        let report = fixture.build().expect("valid current report fixture");
        assert_eq!(report.schema, "carrick.jit-shape-census.v3");
        assert_eq!(
            report.classifier_schema,
            "carrick.jit-shape-classifier.aarch64.v3"
        );
        let bytes = serialize_census(&report).expect("serialize current report fixture");
        assert_eq!(parse_census_v3(&bytes).unwrap(), report);

        for old in [
            b"{\"schema\":\"carrick.jit-shape-census.v1\"}\n".as_slice(),
            b"{\"schema\":\"carrick.jit-shape-census.v2\"}\n".as_slice(),
        ] {
            assert!(parse_census_v3(old).is_err());
        }

        let mut old_classifier = report;
        old_classifier.classifier_schema = "carrick.jit-shape-classifier.aarch64.v2".into();
        assert!(old_classifier.validate().is_err());
    }

    fn comparison_censuses() -> (JitShapeCensusV3, JitShapeCensusV3) {
        let a = CensusFixture::new()
            .build()
            .expect("build comparison census A");
        let mut b = a.clone();
        b.capture_authority.run_id = "native-shape-comparison-b".to_owned();
        b.capture_receipt_sha256 = "6".repeat(64);
        b.raw_trace_sha256 = "7".repeat(64);
        b.snapshot_manifest_sha256 = "8".repeat(64);
        b.validate().expect("comparison census B remains valid");
        (a, b)
    }

    fn compare_reports(
        a: &JitShapeCensusV3,
        b: &JitShapeCensusV3,
    ) -> anyhow::Result<JitShapeComparisonV1> {
        build_comparison_from_bytes(&serialize_census(a)?, &serialize_census(b)?)
    }

    fn make_comparison_b(report: &mut JitShapeCensusV3) {
        report.capture_authority.run_id = "native-shape-comparison-b".to_owned();
        report.capture_receipt_sha256 = "6".repeat(64);
        report.raw_trace_sha256 = "7".repeat(64);
        report.snapshot_manifest_sha256 = "8".repeat(64);
        report
            .validate()
            .expect("comparison B remains a valid v3 census");
    }

    #[test]
    fn jit_shape_compare_rejects_every_capture_and_census_determinant_drift() {
        type Mutation = fn(&mut JitShapeCensusV3);
        let mutations: &[(&str, Mutation)] = &[
            ("capture git", |report| {
                report.capture_authority.git_head = "a".repeat(40)
            }),
            ("capture executable", |report| {
                report.capture_authority.executable_sha256 = "a".repeat(64)
            }),
            ("capture host", |report| {
                report.capture_authority.host = "other-capture-host".into()
            }),
            ("capture architecture", |report| {
                report.capture_authority.host_arch = "x86_64".into()
            }),
            ("capture OS build", |report| {
                report.capture_authority.os_build = "26B1".into()
            }),
            ("profile", |report| {
                report.capture_authority.profile = "other".into()
            }),
            ("raw schema", |report| {
                report.capture_authority.raw_schema = "carrick.native-shape.raw.v1".into()
            }),
            ("D template", |report| {
                report.capture_authority.program_template_sha256 = "a".repeat(64)
            }),
            ("canonical image", |report| {
                let image = "docker.io/library/ubuntu@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
                report.capture_authority.image = image.into();
                report.capture_authority.target_argv[3] = image.into();
                report.capture_authority.target_argv_sha256 =
                    argv_sha256(&report.capture_authority.target_argv).unwrap();
            }),
            ("target argv", |report| {
                report.capture_authority.target_argv[4] = "/bin/false".into();
                report.capture_authority.target_argv_sha256 =
                    argv_sha256(&report.capture_authority.target_argv).unwrap();
            }),
            ("target argv digest", |report| {
                report.capture_authority.target_argv_sha256 = "a".repeat(64)
            }),
            ("sampling frequency", |report| {
                report.capture_authority.sampling_hz = 998
            }),
            ("classifier schema", |report| {
                report.classifier_schema = "carrick.jit-shape-classifier.aarch64.v2".into()
            }),
            ("census git", |report| {
                report.census_identity.git_head = "a".repeat(40)
            }),
            ("census executable", |report| {
                report.census_identity.executable_sha256 = "a".repeat(64)
            }),
            ("census host", |report| {
                report.census_identity.host = "other-census-host".into()
            }),
            ("census architecture", |report| {
                report.census_identity.host_arch = "x86_64".into()
            }),
            ("census OS build", |report| {
                report.census_identity.os_build = "26B1".into()
            }),
        ];

        let (a, b) = comparison_censuses();
        compare_reports(&a, &b).expect("matching comparison determinants should pass");

        for (name, mutate) in mutations {
            let (a, mut b) = comparison_censuses();
            mutate(&mut b);
            let error = compare_reports(&a, &b)
                .expect_err(&format!("{name} determinant drift must be rejected"));
            assert!(
                format!("{error:#}").contains(name.split_whitespace().next().unwrap()),
                "unexpected {name} rejection: {error:#}",
            );
        }
    }

    #[test]
    fn jit_shape_compare_preserves_distinct_per_run_qualification_receipts() {
        let (a, mut b) = comparison_censuses();
        let a_birth = a.capture_authority.birth_qualification_sha256.clone();
        let a_terminal = a.capture_authority.terminal_qualification_sha256.clone();
        let b_birth = "a".repeat(64);
        let b_terminal = "b".repeat(64);
        b.capture_authority.birth_qualification_sha256 = b_birth.clone();
        b.capture_authority.terminal_qualification_sha256 = b_terminal.clone();
        b.validate()
            .expect("distinct per-run qualification receipts remain valid v3 provenance");

        let comparison = compare_reports(&a, &b)
            .expect("per-run qualification receipt hashes are not pair determinants");
        assert_eq!(
            comparison
                .determinants
                .a_capture_authority
                .birth_qualification_sha256,
            a_birth,
        );
        assert_eq!(
            comparison
                .determinants
                .a_capture_authority
                .terminal_qualification_sha256,
            a_terminal,
        );
        assert_eq!(
            comparison
                .determinants
                .b_capture_authority
                .birth_qualification_sha256,
            b_birth,
        );
        assert_eq!(
            comparison
                .determinants
                .b_capture_authority
                .terminal_qualification_sha256,
            b_terminal,
        );
    }

    #[test]
    fn jit_shape_compare_rejects_invalid_per_run_qualification_receipts() {
        let invalid_hashes = ["A".repeat(64), "z".repeat(64), "a".repeat(63)];

        for invalid in invalid_hashes {
            let (a, mut b) = comparison_censuses();
            b.capture_authority.birth_qualification_sha256 = invalid.clone();
            let error = compare_reports(&a, &b)
                .expect_err("invalid birth qualification receipt hash must reject");
            assert!(
                format!("{error:#}").contains("birth_qualification_sha256"),
                "unexpected birth receipt rejection: {error:#}",
            );

            let (a, mut b) = comparison_censuses();
            b.capture_authority.terminal_qualification_sha256 = invalid;
            let error = compare_reports(&a, &b)
                .expect_err("invalid terminal qualification receipt hash must reject");
            assert!(
                format!("{error:#}").contains("terminal_qualification_sha256"),
                "unexpected terminal receipt rejection: {error:#}",
            );
        }
    }

    #[test]
    fn jit_shape_compare_requires_independent_strict_v3_inputs() {
        let (a, b) = comparison_censuses();
        let a_bytes = serialize_census(&a).unwrap();
        assert!(build_comparison_from_bytes(&a_bytes, &a_bytes).is_err());

        let mut duplicate = b.clone();
        duplicate.capture_authority.run_id = a.capture_authority.run_id.clone();
        assert!(compare_reports(&a, &duplicate).is_err());

        let mut duplicate = b.clone();
        duplicate.capture_receipt_sha256 = a.capture_receipt_sha256.clone();
        assert!(compare_reports(&a, &duplicate).is_err());

        let mut duplicate = b.clone();
        duplicate.raw_trace_sha256 = a.raw_trace_sha256.clone();
        assert!(compare_reports(&a, &duplicate).is_err());

        let mut duplicate = b.clone();
        duplicate.snapshot_manifest_sha256 = a.snapshot_manifest_sha256.clone();
        assert!(compare_reports(&a, &duplicate).is_err());

        for old in [
            b"{\"schema\":\"carrick.jit-shape-census.v1\"}\n".as_slice(),
            b"{\"schema\":\"carrick.jit-shape-census.v2\"}\n".as_slice(),
        ] {
            assert!(build_comparison_from_bytes(old, &serialize_census(&b).unwrap()).is_err());
        }

        let mut incomplete = b.clone();
        incomplete.words.pop();
        let mut incomplete_bytes = serde_json::to_vec(&incomplete).unwrap();
        incomplete_bytes.push(b'\n');
        assert!(build_comparison_from_bytes(&a_bytes, &incomplete_bytes).is_err());

        let mut duplicate = b;
        duplicate.families.push(duplicate.families[0].clone());
        let mut duplicate_bytes = serde_json::to_vec(&duplicate).unwrap();
        duplicate_bytes.push(b'\n');
        assert!(build_comparison_from_bytes(&a_bytes, &duplicate_bytes).is_err());
    }

    #[test]
    fn jit_shape_compare_full_outer_joins_family_word_and_compound_context_keys() {
        let a = census_fixture_with_words(&[0xf942_3791, 0xc8df_fe73, 0x1400_0000])
            .build()
            .expect("build outer-join census A");
        let mut b = census_fixture_with_words(&[0xa901_0791, 0xc8df_fe73, 0x1400_0000])
            .build()
            .expect("build outer-join census B");
        make_comparison_b(&mut b);

        let comparison = compare_reports(&a, &b).expect("build full outer join");
        assert_eq!(comparison.family_rows.len(), 4);
        assert_eq!(comparison.word_rows.len(), 4);
        assert_eq!(comparison.context_rows.len(), 2);
        assert!(comparison.family_rows.iter().any(|row| {
            matches!(
                &row.key,
                ComparisonKey::Family {
                    evidence_class: EvidenceClass::ExactAmbiguous,
                    family,
                } if family == "guard-ldar"
            )
        }));

        let load = comparison
            .family_rows
            .iter()
            .find(|row| {
                matches!(
                    &row.key,
                    ComparisonKey::Family { family, .. } if family == "ctx-load64"
                )
            })
            .expect("A-only context-load family remains visible");
        assert_eq!(
            load.a.share_of_all_cpu,
            CensusFraction {
                numerator: 1,
                denominator: 3
            }
        );
        assert_eq!(load.b.samples, 0);
        assert_eq!(
            load.b.share_of_jit,
            CensusFraction {
                numerator: 0,
                denominator: 3
            }
        );
        assert_eq!(
            load.b.share_of_all_cpu,
            CensusFraction {
                numerator: 0,
                denominator: 3
            }
        );

        let pair = comparison
            .context_rows
            .iter()
            .find(|row| {
                matches!(
                    &row.key,
                    ComparisonKey::Context {
                        second: Some(_),
                        ..
                    }
                )
            })
            .expect("B-only pair context remains compound");
        let ComparisonKey::Context { first, second, .. } = &pair.key else {
            panic!("expected compound context key");
        };
        assert_eq!((first.slot, first.physical_register), (16, 17));
        assert_eq!(
            second
                .as_ref()
                .map(|operand| (operand.slot, operand.physical_register)),
            Some((24, 1)),
        );
        assert_eq!(pair.a.samples, 0);
        assert_eq!(pair.b.samples, 1);
    }

    #[test]
    fn jit_shape_compare_crossing_gate_uses_exact_boundaries_and_fails_on_overflow() {
        let share = |numerator, denominator| CensusFraction {
            numerator,
            denominator,
        };
        assert!(
            !mechanical_crossing_gate(&share(9_999, 100_000), &share(9_999, 100_000),)
                .unwrap()
                .0
        );
        assert!(
            mechanical_crossing_gate(&share(10_000, 100_000), &share(10_000, 100_000),)
                .unwrap()
                .0
        );
        assert!(
            mechanical_crossing_gate(&share(10_001, 100_000), &share(10_001, 100_000),)
                .unwrap()
                .0
        );

        for (b, expected) in [(14_999, true), (15_000, true), (15_001, false)] {
            let (crosses, drift) =
                mechanical_crossing_gate(&share(10_000, 100_000), &share(b, 100_000)).unwrap();
            assert_eq!(crosses, expected, "wrong exact drift boundary for {b}");
            assert_eq!(
                drift,
                ComparisonFraction {
                    numerator: u128::from(b - 10_000) * 100_000,
                    denominator: 10_000_000_000,
                },
            );
        }

        assert!(
            mechanical_crossing_gate(&share(u64::MAX, u64::MAX), &share(u64::MAX, u64::MAX),)
                .is_err()
        );
    }

    #[test]
    fn jit_shape_compare_sorts_crossings_by_exact_minimum_then_key_and_is_symmetric() {
        let a_words = [
            0x1400_0000,
            0x1400_0000,
            0x1400_0000,
            0x1400_0000,
            0xf942_3791,
            0xf942_3791,
            0xf942_3791,
            0xf940_0240,
            0xf940_0240,
            0xd503_201f,
        ];
        let b_words = [
            0x1400_0000,
            0x1400_0000,
            0x1400_0000,
            0x1400_0000,
            0x1400_0000,
            0xf942_3791,
            0xf942_3791,
            0xf940_0240,
            0xf940_0240,
            0xd503_201f,
        ];
        let a = census_fixture_with_words(&a_words).build().unwrap();
        let mut b = census_fixture_with_words(&b_words).build().unwrap();
        make_comparison_b(&mut b);

        let forward = compare_reports(&a, &b).expect("compare A/B");
        let reverse = compare_reports(&b, &a).expect("compare B/A");
        assert!(forward.mechanical_crossings.len() >= 4);
        for pair in forward.mechanical_crossings.windows(2) {
            let order = compare_fraction(
                &pair[0].minimum_all_cpu_share,
                &pair[1].minimum_all_cpu_share,
            )
            .unwrap();
            assert!(
                order.is_gt() || (order.is_eq() && pair[0].key < pair[1].key),
                "crossings are not sorted by descending exact minimum then key",
            );
        }
        assert_eq!(
            forward
                .mechanical_crossings
                .iter()
                .map(|row| &row.key)
                .collect::<Vec<_>>(),
            reverse
                .mechanical_crossings
                .iter()
                .map(|row| &row.key)
                .collect::<Vec<_>>(),
        );
        for (forward, reverse) in forward
            .mechanical_crossings
            .iter()
            .zip(&reverse.mechanical_crossings)
        {
            assert_eq!(forward.a, reverse.b);
            assert_eq!(forward.b, reverse.a);
            assert_eq!(
                forward.absolute_all_cpu_drift,
                reverse.absolute_all_cpu_drift
            );
        }
    }

    #[test]
    fn jit_shape_compare_v1_is_canonical_strict_and_self_validating() {
        let (a, b) = comparison_censuses();
        let report = compare_reports(&a, &b).expect("build strict comparison report");
        let first = serialize_comparison(&report).expect("serialize comparison once");
        let second = serialize_comparison(&report).expect("serialize comparison twice");
        assert_eq!(first, second);
        assert_eq!(parse_comparison_v1(&first).unwrap(), report);
        assert_eq!(first.last(), Some(&b'\n'));
        assert_eq!(first.iter().filter(|byte| **byte == b'\n').count(), 1);

        let wide = ComparisonFraction {
            numerator: u128::from(u64::MAX) + 1,
            denominator: u128::from(u64::MAX) + 2,
        };
        let encoded = serde_json::to_vec(&wide).expect("serialize u128 exact fraction");
        assert_eq!(
            serde_json::from_slice::<ComparisonFraction>(&encoded)
                .expect("deserialize u128 exact fraction"),
            wide,
        );

        let mut unknown: serde_json::Value = serde_json::from_slice(&first).unwrap();
        unknown["unknown"] = true.into();
        let mut unknown = serde_json::to_vec(&unknown).unwrap();
        unknown.push(b'\n');
        assert!(parse_comparison_v1(&unknown).is_err());

        let mut noncanonical = first.clone();
        noncanonical.insert(noncanonical.len() - 1, b' ');
        assert!(parse_comparison_v1(&noncanonical).is_err());

        let mut mutations = Vec::<(&str, JitShapeComparisonV1)>::new();
        let mut changed = report.clone();
        changed.schema = "carrick.jit-shape-comparison.v0".into();
        mutations.push(("schema", changed));
        let mut changed = report.clone();
        changed.a_sha256 = "0".into();
        mutations.push(("input hash", changed));
        let mut changed = report.clone();
        changed.determinants.b_raw_trace_sha256 = changed.determinants.a_raw_trace_sha256.clone();
        mutations.push(("duplicate capture", changed));
        let mut changed = report.clone();
        changed.determinants.b_census_identity.host_arch = "x86_64".into();
        mutations.push(("non-AArch64 census identity", changed));
        let mut changed = report.clone();
        changed.family_rows.pop();
        mutations.push(("missing family", changed));
        let mut changed = report.clone();
        changed.word_rows.push(changed.word_rows[0].clone());
        mutations.push(("duplicate word", changed));
        let mut changed = report.clone();
        changed.context_rows.reverse();
        mutations.push(("context order", changed));
        let mut changed = report.clone();
        let pair = changed
            .context_rows
            .iter_mut()
            .find_map(|row| match &mut row.key {
                ComparisonKey::Context {
                    second: Some(second),
                    ..
                } => Some(second),
                _ => None,
            })
            .expect("comparison fixture contains a pair context");
        pair.physical_register = 2;
        mutations.push(("compound context", changed));
        let mut changed = report.clone();
        changed.family_rows[0].a.share_of_all_cpu.numerator += 1;
        mutations.push(("share", changed));
        let mut changed = report.clone();
        changed.word_rows[0].absolute_all_cpu_drift.numerator += 1;
        mutations.push(("drift", changed));
        let mut changed = report.clone();
        changed.mechanical_crossings.pop();
        mutations.push(("crossing", changed));
        for (name, changed) in mutations {
            assert!(changed.validate().is_err(), "accepted {name} mutation");
        }
    }

    #[test]
    fn jit_shape_compare_publication_is_no_clobber_and_race_safe() {
        let (a, b) = comparison_censuses();
        let report = compare_reports(&a, &b).unwrap();
        let reversed = compare_reports(&b, &a).unwrap();
        let expected = serialize_comparison(&report).unwrap();
        let reversed_expected = serialize_comparison(&reversed).unwrap();

        let mut stdout = Vec::new();
        publish_comparison(&report, None, &mut stdout).unwrap();
        assert_eq!(stdout, expected);

        let root = tempfile::tempdir().unwrap();
        let existing = root.path().join("existing.json");
        std::fs::write(&existing, b"preserve-me\n").unwrap();
        let error = publish_comparison(&report, Some(&existing), &mut Vec::new())
            .expect_err("comparison publication must preserve an existing artifact");
        assert!(format!("{error:#}").contains("already exists"));
        assert_eq!(std::fs::read(&existing).unwrap(), b"preserve-me\n");

        let race = std::sync::Arc::new(root.path().join("race.json"));
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let mut handles = Vec::new();
        for report in [report, reversed] {
            let race = std::sync::Arc::clone(&race);
            let barrier = std::sync::Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                publish_comparison(&report, Some(race.as_path()), &mut Vec::new())
            }));
        }
        let results = handles
            .into_iter()
            .map(|handle| handle.join().expect("publisher thread did not panic"))
            .collect::<Vec<_>>();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(results.iter().filter(|result| result.is_err()).count(), 1);
        let winner = std::fs::read(race.as_path()).unwrap();
        assert!(winner == expected || winner == reversed_expected);
    }

    #[test]
    fn jit_shape_compare_runner_binds_stable_executor_identity_before_publication() {
        let (a, b) = comparison_censuses();
        let root = tempfile::tempdir().unwrap();
        let a_path = root.path().join("a.json");
        let b_path = root.path().join("b.json");
        std::fs::write(&a_path, serialize_census(&a).unwrap()).unwrap();
        std::fs::write(&b_path, serialize_census(&b).unwrap()).unwrap();
        let expected = serialize_comparison(&compare_reports(&a, &b).unwrap()).unwrap();

        let mut calls = 0_u8;
        let mut stdout = Vec::new();
        run_jit_shape_compare_with_identity_capture(&a_path, &b_path, None, &mut stdout, || {
            calls += 1;
            Ok(a.census_identity.clone())
        })
        .expect("stable comparator executor should publish");
        assert_eq!(calls, 2);
        assert_eq!(stdout, expected);

        let mut mismatch = a.census_identity.clone();
        mismatch.executable_sha256 = "a".repeat(64);
        let mut unpublished = Vec::new();
        assert!(
            run_jit_shape_compare_with_identity_capture(
                &a_path,
                &b_path,
                None,
                &mut unpublished,
                || Ok(mismatch.clone()),
            )
            .is_err()
        );
        assert!(unpublished.is_empty());

        let mut calls = 0_u8;
        let mut unpublished = Vec::new();
        assert!(
            run_jit_shape_compare_with_identity_capture(
                &a_path,
                &b_path,
                None,
                &mut unpublished,
                || {
                    calls += 1;
                    let mut identity = a.census_identity.clone();
                    if calls == 2 {
                        identity.git_head = "a".repeat(40);
                    }
                    Ok(identity)
                },
            )
            .is_err()
        );
        assert_eq!(calls, 2);
        assert!(unpublished.is_empty());
    }

    #[test]
    fn jit_shape_classifier_freezes_exact_masks_evidence_and_precedence() {
        let inserted = [
            (0xf902_3791, EvidenceClass::InsertedExact, "ctx-store64"),
            (0xf942_3791, EvidenceClass::InsertedExact, "ctx-load64"),
            (0xb902_3791, EvidenceClass::InsertedExact, "ctx-store32"),
            (0xb942_3791, EvidenceClass::InsertedExact, "ctx-load32"),
            (0xa900_0791, EvidenceClass::InsertedExact, "ctx-pair"),
            (0xa940_0791, EvidenceClass::InsertedExact, "ctx-pair"),
            (0xc8df_fe73, EvidenceClass::ExactAmbiguous, "guard-ldar"),
            (0xd340_0012, EvidenceClass::InsertedExact, "window-ubfm-x18"),
            (0xb400_0012, EvidenceClass::InsertedExact, "window-cbz-x18"),
            (0xb257_0013, EvidenceClass::ExactAmbiguous, "bias-orr"),
            (0xb251_0013, EvidenceClass::ExactAmbiguous, "bias-orr"),
            (0xd51b_4211, EvidenceClass::ExactAmbiguous, "nzcv-msr"),
            (0xd53b_4211, EvidenceClass::ExactAmbiguous, "nzcv-mrs"),
            (
                0x5280_0011,
                EvidenceClass::ExactAmbiguous,
                "x17-materialize",
            ),
            (
                0x7280_0011,
                EvidenceClass::ExactAmbiguous,
                "x17-materialize",
            ),
            (
                0xd280_0011,
                EvidenceClass::ExactAmbiguous,
                "x17-materialize",
            ),
            (
                0xf280_0011,
                EvidenceClass::ExactAmbiguous,
                "x17-materialize",
            ),
            (0x5280_0012, EvidenceClass::InsertedExact, "x18-materialize"),
            (0x7280_0012, EvidenceClass::InsertedExact, "x18-materialize"),
            (0xd280_0012, EvidenceClass::InsertedExact, "x18-materialize"),
            (0xf280_0012, EvidenceClass::InsertedExact, "x18-materialize"),
            (0xd61f_0220, EvidenceClass::InsertedExact, "br-x17"),
            (0xf940_0240, EvidenceClass::InsertedExact, "x18-based-ldst"),
            (0xf900_0240, EvidenceClass::InsertedExact, "x18-based-ldst"),
        ];
        for (word, evidence_class, family) in inserted {
            assert_eq!(
                classify(word),
                Classification {
                    evidence_class,
                    family,
                },
                "word {word:#010x}"
            );
        }

        let one_bit_neighbors = [
            (
                0xf902_3791 ^ (1 << 26),
                EvidenceClass::InsertedExact,
                "ctx-store64",
            ),
            (
                0xf942_3791 ^ (1 << 26),
                EvidenceClass::InsertedExact,
                "ctx-load64",
            ),
            (
                0xb902_3791 ^ (1 << 26),
                EvidenceClass::InsertedExact,
                "ctx-store32",
            ),
            (
                0xb942_3791 ^ (1 << 26),
                EvidenceClass::InsertedExact,
                "ctx-load32",
            ),
            (
                0xa900_0791 ^ (1 << 26),
                EvidenceClass::InsertedExact,
                "ctx-pair",
            ),
            (
                0xc8df_fe73 ^ (1 << 10),
                EvidenceClass::ExactAmbiguous,
                "guard-ldar",
            ),
            (
                0xd340_0012 ^ (1 << 22),
                EvidenceClass::InsertedExact,
                "window-ubfm-x18",
            ),
            (
                0xb400_0012 ^ (1 << 24),
                EvidenceClass::InsertedExact,
                "window-cbz-x18",
            ),
            (
                0xb257_0013 ^ (1 << 10),
                EvidenceClass::ExactAmbiguous,
                "bias-orr",
            ),
            (
                0xd51b_4211 ^ (1 << 5),
                EvidenceClass::ExactAmbiguous,
                "nzcv-msr",
            ),
            (
                0xd53b_4211 ^ (1 << 5),
                EvidenceClass::ExactAmbiguous,
                "nzcv-mrs",
            ),
            (
                0xd280_0011 ^ 1,
                EvidenceClass::ExactAmbiguous,
                "x17-materialize",
            ),
            (
                0xd280_0012 ^ 1,
                EvidenceClass::InsertedExact,
                "x18-materialize",
            ),
            (0xd61f_0220 ^ 1, EvidenceClass::InsertedExact, "br-x17"),
            (
                0xf940_0240 ^ (1 << 5),
                EvidenceClass::InsertedExact,
                "x18-based-ldst",
            ),
        ];
        for (word, excluded_class, excluded_family) in one_bit_neighbors {
            let observed = classify(word);
            assert!(
                observed
                    != Classification {
                        evidence_class: excluded_class,
                        family: excluded_family,
                    },
                "one-bit neighbor {word:#010x} stayed in {excluded_family}"
            );
        }

        // Exact DSR shapes must win over broader guest families.
        assert_eq!(classify(0xb400_0012).family, "window-cbz-x18");
        assert_eq!(classify(0xf940_0240).family, "x18-based-ldst");
        assert_eq!(classify(0xd61f_0220).family, "br-x17");
    }

    #[test]
    fn jit_shape_classifier_freezes_guest_descriptive_families() {
        let cases = [
            (0xd61f_0000, "br-reg"),
            (0xd65f_0000, "ret"),
            (0x1400_0000, "b/bl"),
            (0x5400_0000, "b.cond"),
            (0xb400_0000, "cbz/cbnz"),
            (0x3600_0000, "tbz/tbnz"),
            (0xf940_0020, "ldst-imm"),
            // Preserve the Python precedence: this encoding also matches the
            // earlier immediate-load/store mask and therefore lands there.
            (0x3d40_0020, "ldst-imm"),
            (0xa900_0440, "ldst-pair"),
            (0x3820_0800, "ldst-reg"),
            (0x9100_0400, "add/sub"),
            (0xd280_0000, "mov/logic-imm"),
            (0x0a00_0000, "logic-reg"),
            (0x1b00_0000, "muladd"),
            (0x0e00_0000, "simd"),
            (0xd503_201f, "other"),
        ];
        for (word, family) in cases {
            assert_eq!(
                classify(word),
                Classification {
                    evidence_class: EvidenceClass::GuestDescriptive,
                    family,
                },
                "word {word:#010x}"
            );
        }
    }

    #[test]
    fn jit_shape_context_decoder_covers_64_32_and_pair_rows() {
        let cases = [
            (0xf942_3791, Direction::Load, (1128_i64, 17), None),
            (0xf902_3791, Direction::Store, (1128, 17), None),
            (0xb942_3791, Direction::Load, (564, 17), None),
            (0xb902_3791, Direction::Store, (564, 17), None),
            (0xa941_0791, Direction::Load, (16, 17), Some((24, 1))),
            (0xa901_0791, Direction::Store, (16, 17), Some((24, 1))),
            (0xa97f_8b83, Direction::Load, (-8, 3), Some((0, 2))),
        ];
        for (word, direction, first, second) in cases {
            let access = decode_context(word).expect("exact context access");
            let observed_first = (access.first.slot, access.first.register);
            let observed_second = access
                .second
                .map(|operand| (operand.slot, operand.register));
            assert_eq!(
                (access.direction, observed_first, observed_second),
                (direction, first, second),
                "word {word:#010x}"
            );
        }
        assert_eq!(decode_context(0xf940_0020), None);
    }

    #[test]
    fn jit_shape_guest_register_extraction_matches_frozen_rules() {
        let cases: &[(u32, Option<&[u8]>)] = &[
            (0x1400_0000, Some(&[])),
            (0x5400_0000, Some(&[])),
            (0xb400_0011, Some(&[17])),
            (0x3600_0012, Some(&[18])),
            (0xf940_0431, Some(&[1, 17])),
            (0xa940_0c51, Some(&[2, 3, 17])),
            (0x3823_0851, Some(&[2, 3, 17])),
            // Preserve Python's operand precedence: the broad load/store
            // predicate claims this word before the data-processing rule.
            (0x8b03_0051, Some(&[2, 17])),
            (0xd280_0011, Some(&[17])),
            (0xd503_201f, None),
        ];
        for (word, expected) in cases {
            let expected = expected.map(|registers| registers.iter().copied().collect());
            assert_eq!(guest_registers(*word), expected, "word {word:#010x}");
        }
    }

    #[test]
    fn jit_shape_classifier_freezes_python_migration_population() {
        let samples = [
            (0xf902_3791_u32, 3_u64),
            (0xf942_3791, 5),
            (0xb902_3791, 7),
            (0xb942_3791, 11),
            (0xa900_0791, 13),
            (0xa940_0791, 17),
            (0xc8df_fe73, 19),
            (0xd340_0012, 23),
            (0xb400_0012, 29),
            (0xb257_0013, 31),
            (0xb251_0013, 37),
            (0xd51b_4211, 41),
            (0xd53b_4211, 43),
            (0xd280_0011, 47),
            (0xf280_0011, 53),
            (0xd280_0012, 59),
            (0xf280_0012, 61),
            (0xd61f_0220, 67),
            (0xf940_0240, 71),
            (0xf900_0240, 73),
            (0xf902_3791 ^ (1 << 26), 79),
            (0xf942_3791 ^ (1 << 26), 83),
            (0xb902_3791 ^ (1 << 26), 89),
            (0xb942_3791 ^ (1 << 26), 97),
            (0xa900_0791 ^ (1 << 26), 101),
            (0xc8df_fe73 ^ (1 << 10), 103),
            (0xd340_0012 ^ (1 << 22), 107),
            (0xb400_0012 ^ (1 << 24), 109),
            (0xb257_0013 ^ (1 << 10), 113),
            (0xd51b_4211 ^ (1 << 5), 127),
            (0xd53b_4211 ^ (1 << 5), 131),
            (0xd280_0011 ^ 1, 137),
            (0xd280_0012 ^ 1, 139),
            (0xd61f_0220 ^ 1, 149),
            (0xf940_0240 ^ (1 << 5), 151),
            (0xd61f_0000, 157),
            (0xd65f_0000, 163),
            (0x1400_0000, 167),
            (0x5400_0000, 173),
            (0xb400_0000, 179),
            (0x3600_0000, 181),
            (0xf940_0020, 191),
            (0x3d40_0020, 193),
            (0xa900_0440, 197),
            (0x3820_0800, 199),
            (0x9100_0400, 211),
            (0xd280_0000, 223),
            (0x0a00_0000, 227),
            (0x1b00_0000, 229),
            (0x0e00_0000, 233),
            (0xd503_201f, 239),
            // Duplicate words prove population aggregation, not only labels.
            (0xf942_3791, 241),
            (0x1400_0000, 251),
        ];

        let mut families = BTreeMap::<String, u64>::new();
        let mut words = BTreeMap::<(String, u32), u64>::new();
        for &(word, count) in &samples {
            let classification = classify(word);
            let prefix = match classification.evidence_class {
                EvidenceClass::InsertedExact | EvidenceClass::ExactAmbiguous => "dsr",
                EvidenceClass::GuestDescriptive => "guest",
            };
            let family = format!("{prefix}:{}", classification.family);
            *families.entry(family.clone()).or_default() += count;
            *words.entry((family, word)).or_default() += count;
        }
        let rust_population = serde_json::json!({
            "families": families.into_iter().collect::<Vec<_>>(),
            "words": words
                .into_iter()
                .map(|((family, word), count)| (family, word, count))
                .collect::<Vec<_>>(),
        });
        let canonical = serde_json::to_vec(&rust_population).unwrap();
        assert_eq!(samples.iter().map(|(_, count)| count).sum::<u64>(), 6079);
        assert_eq!(rust_population["families"].as_array().unwrap().len(), 30);
        assert_eq!(rust_population["words"].as_array().unwrap().len(), 51);
        assert_eq!(
            format!("{:x}", Sha256::digest(canonical)),
            "fe2b3e6593d3a0b191cfda7a61687f9f4e839031d19fe5bf76cb78fe11a53fbb",
        );
    }
}
