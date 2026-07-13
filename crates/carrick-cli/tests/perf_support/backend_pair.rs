use super::provenance::HostFacts;
use super::stats::{RatioInterval, Summary, bootstrap_median_ratio, summarize};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::Path;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CarrickBackend {
    Native16k,
    Hvf,
}

pub const BACKEND_PAIR_ORDER: [CarrickBackend; 4] = [
    CarrickBackend::Native16k,
    CarrickBackend::Hvf,
    CarrickBackend::Hvf,
    CarrickBackend::Native16k,
];

#[derive(Debug, PartialEq)]
pub struct BackendPairSamples {
    pub native16k: Vec<f64>,
    pub hvf: Vec<f64>,
}

pub fn collect_backend_pair_once<F>(mut run: F) -> Result<Vec<(CarrickBackend, f64)>, String>
where
    F: FnMut(CarrickBackend) -> Result<f64, String>,
{
    BACKEND_PAIR_ORDER
        .into_iter()
        .map(|backend| run(backend).map(|value| (backend, value)))
        .collect()
}

/// Collect complete ABBA cycles serially. Cooldown follows every completed
/// process, including an invalid one, before its error is returned.
pub fn collect_backend_pair<F>(
    cycles: usize,
    cooldown: Duration,
    mut run: F,
) -> Result<BackendPairSamples, String>
where
    F: FnMut(CarrickBackend) -> Result<f64, String>,
{
    let mut samples = BackendPairSamples {
        native16k: Vec::with_capacity(cycles.saturating_mul(2)),
        hvf: Vec::with_capacity(cycles.saturating_mul(2)),
    };
    for _ in 0..cycles {
        for backend in BACKEND_PAIR_ORDER {
            let result = run(backend);
            std::thread::sleep(cooldown);
            let value = result?;
            match backend {
                CarrickBackend::Native16k => samples.native16k.push(value),
                CarrickBackend::Hvf => samples.hvf.push(value),
            }
        }
    }
    if samples.native16k.len() < 2 || samples.hvf.len() < 2 {
        return Err(format!(
            "too few samples: native16k={} hvf={} (need at least 2 each)",
            samples.native16k.len(),
            samples.hvf.len()
        ));
    }
    Ok(samples)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ArtifactIdentity {
    pub kind: String,
    pub label: String,
    pub sha256: String,
}

impl ArtifactIdentity {
    pub fn file(label: impl Into<String>, sha256: impl Into<String>) -> Self {
        Self {
            kind: "file".to_owned(),
            label: label.into(),
            sha256: sha256.into(),
        }
    }

    pub fn from_file(label: impl Into<String>, path: &Path) -> std::io::Result<Self> {
        let bytes = std::fs::read(path)?;
        Ok(Self::file(label, format!("{:x}", Sha256::digest(bytes))))
    }

    pub fn oci(label: impl Into<String>, digest: impl Into<String>) -> Result<Self, String> {
        let digest = digest.into();
        let Some(sha256) = digest.strip_prefix("sha256:") else {
            return Err("OCI identity requires an immutable sha256 digest".to_owned());
        };
        if sha256.is_empty() {
            return Err("OCI identity requires a non-empty sha256 digest".to_owned());
        }
        Ok(Self {
            kind: "oci_image".to_owned(),
            label: label.into(),
            sha256: sha256.to_owned(),
        })
    }
}

pub fn v8_artifact_identity(digest: &str) -> Result<ArtifactIdentity, String> {
    ArtifactIdentity::oci("direct_v8", digest)
}

pub fn validate_same_artifact(
    native: &ArtifactIdentity,
    hvf: &ArtifactIdentity,
) -> Result<(), String> {
    if native.kind != hvf.kind {
        return Err(format!(
            "artifact kind mismatch: native16k={} hvf={}",
            native.kind, hvf.kind
        ));
    }
    if native.label != hvf.label {
        return Err(format!(
            "artifact label mismatch: native16k={} hvf={}",
            native.label, hvf.label
        ));
    }
    if native.sha256 != hvf.sha256 {
        return Err(format!(
            "artifact sha256 mismatch: native16k={} hvf={}",
            native.sha256, hvf.sha256
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize)]
pub struct BackendRun {
    pub schema: u32,
    pub epoch_secs: u64,
    pub schedule: [CarrickBackend; 4],
    pub bootstrap_seed: u64,
    pub bootstrap_resamples: usize,
    pub git_sha: Option<String>,
    pub host: HostFacts,
}

#[derive(Debug, Clone, Serialize)]
pub struct BackendMeasurement {
    pub workload: String,
    pub backend: CarrickBackend,
    pub artifact: ArtifactIdentity,
    pub metric: String,
    pub unit: String,
    pub higher_is_better: bool,
    pub samples: Vec<f64>,
    pub summary: Summary,
}

#[derive(Debug, Clone, Serialize)]
pub struct BackendComparison {
    pub workload: String,
    pub metric: String,
    pub unit: String,
    pub higher_is_better: bool,
    pub ratio_numerator: &'static str,
    pub ratio_denominator: &'static str,
    pub native16k: Summary,
    pub hvf: Summary,
    pub ratio: RatioInterval,
}

pub fn comparison_row(
    workload: &str,
    higher_is_better: bool,
    native16k: &[f64],
    hvf: &[f64],
    seed: u64,
    resamples: usize,
) -> Option<BackendComparison> {
    Some(BackendComparison {
        workload: workload.to_owned(),
        metric: workload.to_owned(),
        unit: "value".to_owned(),
        higher_is_better,
        ratio_numerator: "native16k",
        ratio_denominator: "hvf",
        native16k: summarize(native16k)?,
        hvf: summarize(hvf)?,
        ratio: bootstrap_median_ratio(hvf, native16k, seed, resamples)?,
    })
}

#[derive(Debug, Clone, Serialize)]
pub struct BackendSkip {
    pub workload: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BackendEvidenceRow {
    Run(BackendRun),
    Measurement(BackendMeasurement),
    Comparison(BackendComparison),
    Skip(BackendSkip),
}

pub fn write_backend_rows_atomic(path: &Path, rows: &[BackendEvidenceRow]) -> std::io::Result<()> {
    let tmp = path.with_extension("jsonl.tmp");
    let mut file = std::fs::File::create(&tmp)?;
    for row in rows {
        serde_json::to_writer(&mut file, row).map_err(std::io::Error::other)?;
        writeln!(file)?;
    }
    file.sync_all()?;
    std::fs::rename(tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    #[test]
    fn collector_runs_native_hvf_hvf_native() {
        let seen = RefCell::new(Vec::new());
        collect_backend_pair_once(|backend| {
            seen.borrow_mut().push(backend);
            Ok(1.0)
        })
        .expect("collect");
        assert_eq!(*seen.borrow(), BACKEND_PAIR_ORDER);
    }

    #[test]
    fn collector_rejects_too_few_samples() {
        let error = collect_backend_pair(0, Duration::ZERO, |_| Ok(1.0))
            .expect_err("zero cycles cannot produce a comparison");
        assert!(error.contains("too few samples"));
    }

    #[test]
    fn backend_pair_schedule_is_drift_balanced() {
        assert_eq!(
            BACKEND_PAIR_ORDER,
            [
                CarrickBackend::Native16k,
                CarrickBackend::Hvf,
                CarrickBackend::Hvf,
                CarrickBackend::Native16k,
            ]
        );
    }

    #[test]
    fn comparison_is_native_over_hvf_and_has_no_pass_field() {
        let row = comparison_row("trap_floor", false, &[2.0, 2.2], &[4.0, 4.2], 7, 2_000)
            .expect("comparison");
        assert!(row.ratio.estimate < 1.0);
        let serialized = serde_json::to_string(&row).expect("serialize");
        for policy_field in ["pass", "limit", "threshold", "winner", "global_ranking"] {
            assert!(!serialized.contains(policy_field));
        }
        assert_eq!(row.ratio_numerator, "native16k");
        assert_eq!(row.ratio_denominator, "hvf");
    }

    #[test]
    fn comparison_rejects_artifact_mismatch() {
        assert!(
            validate_same_artifact(
                &ArtifactIdentity::file("probe", "aaa"),
                &ArtifactIdentity::file("probe", "bbb"),
            )
            .expect_err("mismatch")
            .contains("artifact sha256 mismatch")
        );
    }

    #[test]
    fn file_identity_hashes_exact_bytes() {
        let dir = tempfile::tempdir().expect("temporary directory");
        let path = dir.path().join("probe");
        std::fs::write(&path, b"exact probe bytes\n").expect("write artifact");

        let identity = ArtifactIdentity::from_file("probe", &path).expect("identity");

        assert_eq!(identity.kind, "file");
        assert_eq!(identity.label, "probe");
        assert_eq!(
            identity.sha256,
            format!("{:x}", Sha256::digest(b"exact probe bytes\n"))
        );
    }

    #[test]
    fn oci_identity_requires_an_immutable_digest() {
        let identity = ArtifactIdentity::oci("v8", "sha256:abc123").expect("identity");
        assert_eq!(identity.kind, "oci_image");
        assert_eq!(identity.sha256, "abc123");
        assert!(ArtifactIdentity::oci("v8", "ubuntu:24.04").is_err());
    }

    fn skip_row(workload: &str) -> BackendEvidenceRow {
        BackendEvidenceRow::Skip(BackendSkip {
            workload: workload.to_owned(),
            reason: "not a direct ELF case".to_owned(),
        })
    }

    fn representative_rows() -> Vec<BackendEvidenceRow> {
        let comparison =
            comparison_row("trap_floor", false, &[2.0], &[4.0], 7, 10).expect("comparison");
        vec![
            BackendEvidenceRow::Run(BackendRun {
                schema: 1,
                epoch_secs: 1_700_000_000,
                schedule: BACKEND_PAIR_ORDER,
                bootstrap_seed: 7,
                bootstrap_resamples: 10,
                git_sha: Some("abc123".to_owned()),
                host: HostFacts {
                    model: Some("Mac16,12".to_owned()),
                    perf_cores: Some("4".to_owned()),
                    eff_cores: Some("6".to_owned()),
                    macos: Some("26.6".to_owned()),
                    docker_version: None,
                },
            }),
            BackendEvidenceRow::Measurement(BackendMeasurement {
                workload: "trap_floor".to_owned(),
                backend: CarrickBackend::Native16k,
                artifact: ArtifactIdentity::file("probe", "abc"),
                metric: "trap_p50_ns".to_owned(),
                unit: "ns".to_owned(),
                higher_is_better: false,
                samples: vec![2.0],
                summary: summarize(&[2.0]).expect("summary"),
            }),
            BackendEvidenceRow::Comparison(comparison),
            skip_row("mount"),
        ]
    }

    #[test]
    fn atomic_writer_emits_one_object_per_line_and_replaces_destination() {
        let dir = tempfile::tempdir().expect("temporary directory");
        let path = dir.path().join("backend-pair.jsonl");
        std::fs::write(&path, "stale contents\n").expect("seed destination");

        write_backend_rows_atomic(&path, &representative_rows()).expect("atomic write");

        let body = std::fs::read_to_string(&path).expect("read evidence");
        let lines = body.lines().collect::<Vec<_>>();
        assert_eq!(lines.len(), 4);
        assert!(lines.iter().all(|line| {
            serde_json::from_str::<serde_json::Value>(line)
                .expect("JSON object")
                .is_object()
        }));
        assert!(!body.contains("stale contents"));
        assert!(!path.with_extension("jsonl.tmp").exists());
    }

    #[test]
    fn atomic_writer_preserves_destination_when_temp_creation_fails() {
        let dir = tempfile::tempdir().expect("temporary directory");
        let path = dir.path().join("backend-pair.jsonl");
        let tmp = path.with_extension("jsonl.tmp");
        std::fs::write(&path, "authoritative evidence\n").expect("seed destination");
        std::fs::create_dir(&tmp).expect("block temporary file creation");

        assert!(write_backend_rows_atomic(&path, &representative_rows()).is_err());
        assert_eq!(
            std::fs::read_to_string(&path).expect("read destination"),
            "authoritative evidence\n"
        );
    }
}
