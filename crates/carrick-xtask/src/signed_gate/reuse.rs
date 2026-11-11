//! Sealed base-receipt reuse on the same gate Mac (#1918).
//!
//! A reusable base receipt is admissible only when every host, commit, fixture,
//! toolchain and signing input matches field-for-field. Any doubt or mismatch
//! logs a typed [`ReuseMissReason`] and falls back to running `PairSide::Base`.

use crate::accept::{AcceptReceipt, SignedHostIdentity};
use crate::ci_receipt::ReceiptError;
use crate::ci_scaler::REPOSITORY;
use crate::command::run_checked;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::path::Path;
use std::process::Command;

pub const BASE_REUSE_SCHEMA_VERSION: u32 = 1;
pub const SIGNED_GATE_WORKFLOW: &str = ".github/workflows/signed-gate.yml";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BaseReuseKey {
    pub schema_version: u32,
    pub base_sha: String,
    pub host_identity: SignedHostIdentity,
    pub fixture_archive_sha256: String,
    pub fixture_manifest_sha256: String,
    pub fixture_inputs_sha256: String,
    pub fixture_content_sha256: String,
    pub rust_toolchain_sha256: String,
    pub entitlements_sha256: String,
    pub hypervisor_entitlement: bool,
    pub dof_present: bool,
    pub profile: String,
    pub phase: String,
}

impl BaseReuseKey {
    pub fn canonical_json(&self) -> Result<String, ReceiptError> {
        serde_json::to_string(self).map_err(|e| super::fail(e.to_string()))
    }

    pub fn key_sha256(&self) -> Result<String, ReceiptError> {
        let canonical = self.canonical_json()?;
        Ok(format!("{:x}", Sha256::digest(canonical.as_bytes())))
    }

    pub fn artifact_name(&self) -> Result<String, ReceiptError> {
        Ok(format!(
            "signed-base-reuse-{}-{}",
            self.base_sha,
            self.key_sha256()?
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReuseSealMetadata {
    pub key: BaseReuseKey,
    pub key_sha256: String,
    pub source_run_id: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_id: Option<u64>,
}

#[derive(Clone, Debug)]
pub struct ReuseExecutionContext<'a> {
    pub root: &'a Path,
    pub bundle: &'a Path,
    pub host_identity: Option<SignedHostIdentity>,
    pub reuse_dir: &'a Path,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReuseMissReason {
    MainRequestHasNoBaseSide,
    InvalidRequest(String),
    MissingHostIdentity,
    BaseCommitInputUnavailable(String),
    FixtureBundleInvalid(String),
    ArtifactLookupFailed(String),
    NoMatchingArtifact {
        artifact_name: String,
    },
    ArtifactExpired {
        artifact_id: u64,
    },
    UntrustedProducerRun {
        artifact_id: u64,
        run_id: u64,
    },
    ArtifactDownloadFailed {
        artifact_id: u64,
        run_id: u64,
        detail: String,
    },
    MalformedSeal(String),
    SealBaseMismatch {
        expected_base: String,
        actual_base: String,
    },
    KeyFieldMismatch {
        field: &'static str,
        expected: String,
        actual: String,
    },
    InventoryTampered(String),
    ReceiptValidationFailed(String),
    EvidenceAdmissionFailed(String),
    ReceiptKeyInconsistent {
        field: &'static str,
        detail: String,
    },
}

impl ReuseMissReason {
    pub fn variant_name(&self) -> &'static str {
        match self {
            Self::MainRequestHasNoBaseSide => "MainRequestHasNoBaseSide",
            Self::InvalidRequest(_) => "InvalidRequest",
            Self::MissingHostIdentity => "MissingHostIdentity",
            Self::BaseCommitInputUnavailable(_) => "BaseCommitInputUnavailable",
            Self::FixtureBundleInvalid(_) => "FixtureBundleInvalid",
            Self::ArtifactLookupFailed(_) => "ArtifactLookupFailed",
            Self::NoMatchingArtifact { .. } => "NoMatchingArtifact",
            Self::ArtifactExpired { .. } => "ArtifactExpired",
            Self::UntrustedProducerRun { .. } => "UntrustedProducerRun",
            Self::ArtifactDownloadFailed { .. } => "ArtifactDownloadFailed",
            Self::MalformedSeal(_) => "MalformedSeal",
            Self::SealBaseMismatch { .. } => "SealBaseMismatch",
            Self::KeyFieldMismatch { .. } => "KeyFieldMismatch",
            Self::InventoryTampered(_) => "InventoryTampered",
            Self::ReceiptValidationFailed(_) => "ReceiptValidationFailed",
            Self::EvidenceAdmissionFailed(_) => "EvidenceAdmissionFailed",
            Self::ReceiptKeyInconsistent { .. } => "ReceiptKeyInconsistent",
        }
    }
}

impl fmt::Display for ReuseMissReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {:?}", self.variant_name(), self)
    }
}

/// Only `signed-gate.yml` runs on `main` in this repository may supply a
/// reusable base receipt: an automatic `push` to `main` for `base`, or an
/// owner-initiated `workflow_dispatch` on `main`.
pub fn trusted_reuse_run(run: &Value, base: &str) -> bool {
    run["path"] == SIGNED_GATE_WORKFLOW
        && run["head_branch"] == "main"
        && run["repository"]["full_name"] == REPOSITORY
        && run["head_repository"]["full_name"] == REPOSITORY
        && ((run["event"] == "push" && run["head_sha"] == base)
            || (run["event"] == "workflow_dispatch"
                && run["actor"]["login"].as_str().is_some_and(super::allowed)
                && run["triggering_actor"]["login"]
                    .as_str()
                    .is_some_and(super::allowed)))
}

fn ensure_commit_present(root: &Path, commit: &str) -> Result<(), ReuseMissReason> {
    let verify_spec = format!("{commit}^{{commit}}");
    if run_checked("git", ["cat-file", "-e", &verify_spec], Some(root)).is_ok() {
        return Ok(());
    }
    super::fetch_with_retry(
        || run_checked("git", ["fetch", "--no-tags", "origin", commit], Some(root)),
        std::thread::sleep,
    )
    .map_err(|e| ReuseMissReason::BaseCommitInputUnavailable(e.to_string()))?;
    run_checked("git", ["cat-file", "-e", &verify_spec], Some(root))
        .map(|_| ())
        .map_err(|e| ReuseMissReason::BaseCommitInputUnavailable(e.to_string()))
}

fn git_blob_sha256(root: &Path, commit: &str, rel_path: &str) -> Result<String, ReuseMissReason> {
    let ls = run_checked("git", ["ls-tree", commit, "--", rel_path], Some(root))
        .map_err(|e| ReuseMissReason::BaseCommitInputUnavailable(e.to_string()))?;
    let mode = ls.stdout.split_whitespace().next().ok_or_else(|| {
        ReuseMissReason::BaseCommitInputUnavailable(format!(
            "missing {rel_path} in commit {commit}"
        ))
    })?;
    if mode != "100644" && mode != "100755" {
        return Err(ReuseMissReason::BaseCommitInputUnavailable(format!(
            "{rel_path} in {commit} is not a regular file (mode {mode})"
        )));
    }
    let spec = format!("{commit}:{rel_path}");
    let out = Command::new("git")
        .current_dir(root)
        .args(["cat-file", "blob", &spec])
        .output()
        .map_err(|e| ReuseMissReason::BaseCommitInputUnavailable(e.to_string()))?;
    if !out.status.success() {
        return Err(ReuseMissReason::BaseCommitInputUnavailable(format!(
            "git cat-file blob {spec} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(format!("{:x}", Sha256::digest(&out.stdout)))
}

/// Single key computation shared by the `Main` publisher (`prepare_reuse_upload`)
/// and the gate-Mac consumer (`reuse_lookup` and `execute_pair`).
pub fn compute_base_reuse_key(
    root: &Path,
    base_sha: &str,
    host_identity: SignedHostIdentity,
    bundle_path: &Path,
) -> Result<BaseReuseKey, ReuseMissReason> {
    let base_sha =
        super::sha(base_sha).map_err(|e| ReuseMissReason::InvalidRequest(e.to_string()))?;
    if !host_identity.is_complete() {
        return Err(ReuseMissReason::MissingHostIdentity);
    }
    ensure_commit_present(root, &base_sha)?;
    let rust_toolchain_sha256 = git_blob_sha256(root, &base_sha, "rust-toolchain.toml")?;
    let entitlements_sha256 = git_blob_sha256(root, &base_sha, "scripts/entitlements.plist")?;

    let fixture_archive_sha256 = crate::provision::compute_sha256(bundle_path)
        .map_err(|e| ReuseMissReason::FixtureBundleInvalid(e.to_string()))?;
    let unpacked = crate::fixtures::archive::unpack_bundle(bundle_path)
        .map_err(|e| ReuseMissReason::FixtureBundleInvalid(e.to_string()))?;
    // `resolve_bundle` on an explicit path runs the publisher's own
    // manifest and object-integrity check; the manifest it admitted is
    // then parsed here.
    crate::fixtures::resolve_bundle(root, &base_sha, Some(unpacked.manifest()))
        .map_err(|e| ReuseMissReason::FixtureBundleInvalid(e.to_string()))?;
    let manifest: crate::fixtures::Manifest = std::fs::read(unpacked.manifest())
        .map_err(|e| e.to_string())
        .and_then(|bytes| serde_json::from_slice(&bytes).map_err(|e| e.to_string()))
        .map_err(ReuseMissReason::FixtureBundleInvalid)?;
    let bundle_head = String::from(manifest.source_head.clone());
    if bundle_head != base_sha {
        return Err(ReuseMissReason::FixtureBundleInvalid(format!(
            "bundle source_head {bundle_head} differs from base {base_sha}"
        )));
    }
    let fixture_manifest_sha256 = crate::provision::compute_sha256(unpacked.manifest())
        .map_err(|e| ReuseMissReason::FixtureBundleInvalid(e.to_string()))?;
    let fixture_inputs_sha256 = String::from(
        manifest
            .input_identity()
            .map_err(|e| ReuseMissReason::FixtureBundleInvalid(e.to_string()))?,
    );
    let fixture_content_sha256 = String::from(
        manifest
            .content_identity()
            .map_err(|e| ReuseMissReason::FixtureBundleInvalid(e.to_string()))?,
    );

    Ok(BaseReuseKey {
        schema_version: BASE_REUSE_SCHEMA_VERSION,
        base_sha,
        host_identity,
        fixture_archive_sha256,
        fixture_manifest_sha256,
        fixture_inputs_sha256,
        fixture_content_sha256,
        rust_toolchain_sha256,
        entitlements_sha256,
        hypervisor_entitlement: true,
        dof_present: true,
        profile: "no-docker".into(),
        phase: "signed".into(),
    })
}

fn compare_reuse_keys(
    actual: &BaseReuseKey,
    actual_sha256: &str,
    expected: &BaseReuseKey,
) -> Result<(), ReuseMissReason> {
    let check_str = |field: &'static str, got: &str, want: &str| {
        if got == want {
            Ok(())
        } else {
            Err(ReuseMissReason::KeyFieldMismatch {
                field,
                expected: want.to_owned(),
                actual: got.to_owned(),
            })
        }
    };
    if actual.schema_version != expected.schema_version {
        return Err(ReuseMissReason::KeyFieldMismatch {
            field: "schema_version",
            expected: expected.schema_version.to_string(),
            actual: actual.schema_version.to_string(),
        });
    }
    check_str("base_sha", &actual.base_sha, &expected.base_sha)?;
    check_str(
        "host_identity.runner_name",
        &actual.host_identity.runner_name,
        &expected.host_identity.runner_name,
    )?;
    check_str(
        "host_identity.hardware_model",
        &actual.host_identity.hardware_model,
        &expected.host_identity.hardware_model,
    )?;
    check_str(
        "host_identity.product_build",
        &actual.host_identity.product_build,
        &expected.host_identity.product_build,
    )?;
    check_str(
        "fixture_archive_sha256",
        &actual.fixture_archive_sha256,
        &expected.fixture_archive_sha256,
    )?;
    check_str(
        "fixture_manifest_sha256",
        &actual.fixture_manifest_sha256,
        &expected.fixture_manifest_sha256,
    )?;
    check_str(
        "fixture_inputs_sha256",
        &actual.fixture_inputs_sha256,
        &expected.fixture_inputs_sha256,
    )?;
    check_str(
        "fixture_content_sha256",
        &actual.fixture_content_sha256,
        &expected.fixture_content_sha256,
    )?;
    check_str(
        "rust_toolchain_sha256",
        &actual.rust_toolchain_sha256,
        &expected.rust_toolchain_sha256,
    )?;
    check_str(
        "entitlements_sha256",
        &actual.entitlements_sha256,
        &expected.entitlements_sha256,
    )?;
    if actual.hypervisor_entitlement != expected.hypervisor_entitlement {
        return Err(ReuseMissReason::KeyFieldMismatch {
            field: "hypervisor_entitlement",
            expected: expected.hypervisor_entitlement.to_string(),
            actual: actual.hypervisor_entitlement.to_string(),
        });
    }
    if actual.dof_present != expected.dof_present {
        return Err(ReuseMissReason::KeyFieldMismatch {
            field: "dof_present",
            expected: expected.dof_present.to_string(),
            actual: actual.dof_present.to_string(),
        });
    }
    check_str("profile", &actual.profile, &expected.profile)?;
    check_str("phase", &actual.phase, &expected.phase)?;

    let expected_digest = expected
        .key_sha256()
        .map_err(|e| ReuseMissReason::MalformedSeal(e.to_string()))?;
    let recomputed_actual = actual
        .key_sha256()
        .map_err(|e| ReuseMissReason::MalformedSeal(e.to_string()))?;
    if actual_sha256 != expected_digest {
        return Err(ReuseMissReason::KeyFieldMismatch {
            field: "key_sha256",
            expected: expected_digest,
            actual: actual_sha256.to_owned(),
        });
    }
    if recomputed_actual != expected_digest {
        return Err(ReuseMissReason::KeyFieldMismatch {
            field: "key_sha256",
            expected: expected_digest,
            actual: recomputed_actual,
        });
    }
    Ok(())
}

fn verify_receipt_matches_key(
    receipt: &AcceptReceipt,
    key: &BaseReuseKey,
) -> Result<(), ReuseMissReason> {
    if receipt.head != key.base_sha {
        return Err(ReuseMissReason::ReceiptKeyInconsistent {
            field: "head",
            detail: format!(
                "receipt head {} != key base_sha {}",
                receipt.head, key.base_sha
            ),
        });
    }
    if key.profile != "no-docker" || receipt.profile != key.profile {
        return Err(ReuseMissReason::ReceiptKeyInconsistent {
            field: "profile",
            detail: format!(
                "receipt profile {:?}, key profile {:?}",
                receipt.profile, key.profile
            ),
        });
    }
    if key.phase != "signed" || receipt.phase != key.phase {
        return Err(ReuseMissReason::ReceiptKeyInconsistent {
            field: "phase",
            detail: format!(
                "receipt phase {:?}, key phase {:?}",
                receipt.phase, key.phase
            ),
        });
    }
    if !key.host_identity.is_complete()
        || receipt.host_identity.as_ref() != Some(&key.host_identity)
    {
        return Err(ReuseMissReason::ReceiptKeyInconsistent {
            field: "host_identity",
            detail: format!(
                "receipt host_identity {:?} != key host_identity {:?}",
                receipt.host_identity, key.host_identity
            ),
        });
    }
    let artifact =
        receipt
            .artifact
            .as_ref()
            .ok_or_else(|| ReuseMissReason::ReceiptKeyInconsistent {
                field: "artifact",
                detail: "missing signed artifact identity".into(),
            })?;
    if !key.hypervisor_entitlement || artifact.hypervisor_entitlement != key.hypervisor_entitlement
    {
        return Err(ReuseMissReason::ReceiptKeyInconsistent {
            field: "hypervisor_entitlement",
            detail: format!(
                "artifact hypervisor_entitlement={}, key={}",
                artifact.hypervisor_entitlement, key.hypervisor_entitlement
            ),
        });
    }
    if !key.dof_present || artifact.dof_present != key.dof_present {
        return Err(ReuseMissReason::ReceiptKeyInconsistent {
            field: "dof_present",
            detail: format!(
                "artifact dof_present={}, key={}",
                artifact.dof_present, key.dof_present
            ),
        });
    }
    let fv = receipt.fixture_validation.as_ref().ok_or_else(|| {
        ReuseMissReason::ReceiptKeyInconsistent {
            field: "fixture_validation",
            detail: "missing fixture_validation".into(),
        }
    })?;
    if fv.checkout_dirty {
        return Err(ReuseMissReason::ReceiptKeyInconsistent {
            field: "fixture_validation.checkout_dirty",
            detail: "reusable base checkout was dirty".into(),
        });
    }
    if fv.candidate_probes.is_some() {
        return Err(ReuseMissReason::ReceiptKeyInconsistent {
            field: "fixture_validation.candidate_probes",
            detail: "reusable base must not carry candidate_probes".into(),
        });
    }
    if String::from(fv.bundle_source_head.clone()) != key.base_sha {
        return Err(ReuseMissReason::ReceiptKeyInconsistent {
            field: "fixture_validation.bundle_source_head",
            detail: "bundle_source_head differs from key base_sha".into(),
        });
    }
    if String::from(fv.manifest_sha256.clone()) != key.fixture_manifest_sha256 {
        return Err(ReuseMissReason::ReceiptKeyInconsistent {
            field: "fixture_validation.manifest_sha256",
            detail: "manifest_sha256 differs from key".into(),
        });
    }
    if String::from(fv.inputs_sha256.clone()) != key.fixture_inputs_sha256 {
        return Err(ReuseMissReason::ReceiptKeyInconsistent {
            field: "fixture_validation.inputs_sha256",
            detail: "inputs_sha256 differs from key".into(),
        });
    }
    let content = fv.content_sha256.as_ref().map(|h| String::from(h.clone()));
    if content.as_deref() != Some(key.fixture_content_sha256.as_str()) {
        return Err(ReuseMissReason::ReceiptKeyInconsistent {
            field: "fixture_validation.content_sha256",
            detail: "content_sha256 differs from key".into(),
        });
    }
    if let Some(fb) = &receipt.fixture_bundle
        && fb.archive_sha256 != key.fixture_archive_sha256
    {
        return Err(ReuseMissReason::ReceiptKeyInconsistent {
            field: "fixture_bundle.archive_sha256",
            detail: "fixture_bundle archive_sha256 differs from key".into(),
        });
    }
    Ok(())
}

fn verify_reusable_package(
    dir: &Path,
    expected_base: &str,
    expected_key: &BaseReuseKey,
    expected_run_id: Option<u64>,
    require_artifact_id: bool,
) -> Result<super::BaseSeal, ReuseMissReason> {
    let seal_path = dir.join(super::BASE_SEAL);
    let seal: super::BaseSeal = super::read_json(&seal_path)
        .and_then(|v| serde_json::from_value(v).map_err(|e| super::fail(e.to_string())))
        .map_err(|e| ReuseMissReason::MalformedSeal(e.to_string()))?;
    if seal.base != expected_base {
        return Err(ReuseMissReason::SealBaseMismatch {
            expected_base: expected_base.to_owned(),
            actual_base: seal.base,
        });
    }
    let reuse = seal
        .reuse
        .as_ref()
        .ok_or_else(|| ReuseMissReason::MalformedSeal("base-seal.json lacks reuse block".into()))?;
    if reuse.source_run_id == 0 {
        return Err(ReuseMissReason::MalformedSeal(
            "source_run_id must be non-zero".into(),
        ));
    }
    if let Some(run_id) = expected_run_id
        && reuse.source_run_id != run_id
    {
        return Err(ReuseMissReason::SealBaseMismatch {
            expected_base: format!("run_id={run_id}"),
            actual_base: format!("run_id={}", reuse.source_run_id),
        });
    }
    if require_artifact_id && reuse.artifact_id.is_none_or(|id| id == 0) {
        return Err(ReuseMissReason::MalformedSeal(
            "verified reuse seal lacks non-zero artifact_id".into(),
        ));
    }
    compare_reuse_keys(&reuse.key, &reuse.key_sha256, expected_key)?;

    let base_dir = dir.join(super::BASE_DIR);
    super::verify_inventory(&base_dir, &seal.files)
        .map_err(|e| ReuseMissReason::InventoryTampered(e.to_string()))?;

    let receipt = crate::ci_receipt::load(&base_dir.join(super::BASE_RECEIPT))
        .map_err(|e| ReuseMissReason::ReceiptValidationFailed(e.to_string()))?;
    super::validate_side_receipt(super::PairSide::Base, &receipt, expected_base)
        .map_err(|e| ReuseMissReason::ReceiptValidationFailed(e.to_string()))?;
    super::admit_evidence(&base_dir, &receipt)
        .map_err(|e| ReuseMissReason::EvidenceAdmissionFailed(e.to_string()))?;
    super::accept_exit(&base_dir)
        .map_err(|e| ReuseMissReason::EvidenceAdmissionFailed(e.to_string()))?;
    verify_receipt_matches_key(&receipt, expected_key)?;
    Ok(seal)
}

fn copy_regular_tree(src: &Path, dst: &Path) -> Result<(), ReceiptError> {
    fs::create_dir_all(dst).map_err(|e| super::fail(format!("{}: {e}", dst.display())))?;
    let entries = fs::read_dir(src).map_err(|e| super::fail(format!("{}: {e}", src.display())))?;
    for entry in entries {
        let entry = entry.map_err(|e| super::fail(format!("{}: {e}", src.display())))?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        let kind = fs::symlink_metadata(&src_path)
            .map_err(|e| super::fail(format!("{}: {e}", src_path.display())))?
            .file_type();
        if kind.is_dir() {
            copy_regular_tree(&src_path, &dst_path)?;
        } else if kind.is_file() {
            let bytes = fs::read(&src_path)
                .map_err(|e| super::fail(format!("{}: {e}", src_path.display())))?;
            super::write_fresh(&dst_path, bytes)?;
        } else {
            return Err(super::fail(format!(
                "{} is not a regular file",
                src_path.display()
            )));
        }
    }
    Ok(())
}

/// Look up a reusable sealed base receipt on this Mac via GitHub Actions
/// artifacts. Fails closed: any miss or verification failure removes `output`,
/// logs the [`ReuseMissReason`], and exits zero so `execute` runs `PairSide::Base`.
pub fn reuse_lookup(
    root: &Path,
    request_path: &Path,
    bundle_path: &Path,
    output: &Path,
) -> Result<(), ReceiptError> {
    if output.exists() {
        fs::remove_dir_all(output)
            .map_err(|e| super::fail(format!("{}: {e}", output.display())))?;
    }

    let lookup = (|| -> Result<(u64, u64, String), ReuseMissReason> {
        let request: super::Request = super::read_json(request_path)
            .and_then(|v| serde_json::from_value(v).map_err(|e| super::fail(e.to_string())))
            .map_err(|e| ReuseMissReason::InvalidRequest(e.to_string()))?;
        if request.kind == super::RequestKind::Main {
            return Err(ReuseMissReason::MainRequestHasNoBaseSide);
        }
        super::sha(&request.sha).map_err(|e| ReuseMissReason::InvalidRequest(e.to_string()))?;
        let base = super::sha(&request.base)
            .map_err(|e| ReuseMissReason::InvalidRequest(e.to_string()))?;
        let host_identity =
            SignedHostIdentity::capture().ok_or(ReuseMissReason::MissingHostIdentity)?;
        let expected_key = compute_base_reuse_key(root, &base, host_identity, bundle_path)?;
        let artifact_name = expected_key
            .artifact_name()
            .map_err(|e| ReuseMissReason::InvalidRequest(e.to_string()))?;

        let mut artifacts = super::pages(
            &format!("repos/{REPOSITORY}/actions/artifacts?name={artifact_name}&per_page=100"),
            Some("artifacts"),
        )
        .map_err(|e| ReuseMissReason::ArtifactLookupFailed(e.to_string()))?;
        if artifacts.is_empty() {
            return Err(ReuseMissReason::NoMatchingArtifact { artifact_name });
        }
        artifacts.sort_by_key(|a| std::cmp::Reverse(a["id"].as_u64().unwrap_or(0)));

        let mut last_miss = None;
        for artifact in &artifacts {
            let Some(artifact_id) = artifact["id"].as_u64().filter(|id| *id > 0) else {
                last_miss = Some(ReuseMissReason::MalformedSeal(
                    "artifact row lacks positive numeric id".into(),
                ));
                continue;
            };
            if artifact["expired"].as_bool() != Some(false) {
                last_miss = Some(ReuseMissReason::ArtifactExpired { artifact_id });
                continue;
            }
            let Some(run_id) = artifact["workflow_run"]["id"].as_u64().filter(|id| *id > 0) else {
                last_miss = Some(ReuseMissReason::UntrustedProducerRun {
                    artifact_id,
                    run_id: 0,
                });
                continue;
            };
            let run = match super::api(&format!("repos/{REPOSITORY}/actions/runs/{run_id}")) {
                Ok(run) => run,
                Err(e) => {
                    last_miss = Some(ReuseMissReason::ArtifactLookupFailed(e.to_string()));
                    continue;
                }
            };
            if !trusted_reuse_run(&run, &base) {
                last_miss = Some(ReuseMissReason::UntrustedProducerRun {
                    artifact_id,
                    run_id,
                });
                continue;
            }

            let temp =
                tempfile::tempdir().map_err(|e| ReuseMissReason::ArtifactDownloadFailed {
                    artifact_id,
                    run_id,
                    detail: e.to_string(),
                })?;
            let dl_dir = temp.path().join("downloaded");
            if let Err(e) = super::checked(
                "gh",
                &[
                    "run",
                    "download",
                    &run_id.to_string(),
                    "--repo",
                    REPOSITORY,
                    "--name",
                    &artifact_name,
                    "--dir",
                    &dl_dir.to_string_lossy(),
                ],
                None,
            ) {
                last_miss = Some(ReuseMissReason::ArtifactDownloadFailed {
                    artifact_id,
                    run_id,
                    detail: e.to_string(),
                });
                continue;
            }

            let mut seal =
                match verify_reusable_package(&dl_dir, &base, &expected_key, Some(run_id), false) {
                    Ok(seal) => seal,
                    Err(reason) => {
                        last_miss = Some(reason);
                        continue;
                    }
                };
            if let Some(reuse_meta) = seal.reuse.as_mut() {
                reuse_meta.artifact_id = Some(artifact_id);
            }

            let install = (|| -> Result<(), ReuseMissReason> {
                copy_regular_tree(&dl_dir.join(super::BASE_DIR), &output.join(super::BASE_DIR))
                    .map_err(|e| ReuseMissReason::InventoryTampered(e.to_string()))?;
                let bytes = serde_json::to_vec_pretty(&seal)
                    .map_err(|e| ReuseMissReason::MalformedSeal(e.to_string()))?;
                super::write_fresh(&output.join(super::BASE_SEAL), bytes)
                    .map_err(|e| ReuseMissReason::MalformedSeal(e.to_string()))?;
                verify_reusable_package(output, &base, &expected_key, Some(run_id), true).map(drop)
            })();
            match install {
                Ok(()) => return Ok((artifact_id, run_id, base)),
                Err(reason) => {
                    let _ = fs::remove_dir_all(output);
                    last_miss = Some(reason);
                }
            }
        }

        Err(last_miss.unwrap_or(ReuseMissReason::NoMatchingArtifact { artifact_name }))
    })();

    match lookup {
        Ok((artifact_id, run_id, base)) => {
            eprintln!(
                "signed-gate: reusing verified base receipt artifact {artifact_id} from run {run_id} for {base}"
            );
        }
        Err(reason) => {
            let _ = fs::remove_dir_all(output);
            eprintln!("signed-gate: base reuse miss ({reason}); will execute paired base in-job");
        }
    }
    Ok(())
}

/// Verify `ctx.reuse_dir` against live inputs and copy its regular files into
/// `dest_base_dir`. Any mismatch returns a [`ReuseMissReason`] so `execute_pair`
/// cleans up and runs `PairSide::Base` in-job.
pub(crate) fn try_install_reused_base(
    ctx: &ReuseExecutionContext<'_>,
    expected_base: &str,
    dest_base_dir: &Path,
) -> Result<(BTreeMap<String, String>, ReuseSealMetadata), ReuseMissReason> {
    let base =
        super::sha(expected_base).map_err(|e| ReuseMissReason::InvalidRequest(e.to_string()))?;
    let host_identity = ctx
        .host_identity
        .clone()
        .ok_or(ReuseMissReason::MissingHostIdentity)?;
    let expected_key = compute_base_reuse_key(ctx.root, &base, host_identity, ctx.bundle)?;
    let seal = verify_reusable_package(ctx.reuse_dir, &base, &expected_key, None, true)?;
    let reuse_meta = seal
        .reuse
        .ok_or_else(|| ReuseMissReason::MalformedSeal("missing reuse block".into()))?;

    if dest_base_dir.exists() {
        fs::remove_dir_all(dest_base_dir)
            .map_err(|e| ReuseMissReason::InventoryTampered(e.to_string()))?;
    }
    copy_regular_tree(&ctx.reuse_dir.join(super::BASE_DIR), dest_base_dir)
        .map_err(|e| ReuseMissReason::InventoryTampered(e.to_string()))?;
    super::verify_inventory(dest_base_dir, &seal.files)
        .map_err(|e| ReuseMissReason::InventoryTampered(e.to_string()))?;
    Ok((seal.files, reuse_meta))
}

/// Package an admitted, complete `Main` run's evidence into the `base/` +
/// `base-seal.json` layout under the canonical [`BaseReuseKey`].
pub fn prepare_reuse_upload(
    root: &Path,
    request_path: &Path,
    results: &Path,
    bundle_path: &Path,
    run_id: u64,
    output: &Path,
) -> Result<String, ReceiptError> {
    if run_id == 0 {
        return Err(super::fail("run_id must be non-zero"));
    }
    let request: super::Request = serde_json::from_value(super::read_json(request_path)?)
        .map_err(|e| super::fail(e.to_string()))?;
    if request.kind != super::RequestKind::Main {
        return Err(super::fail(
            "only Main requests may publish a reusable base receipt",
        ));
    }
    let base_sha = super::sha(&request.base)?;
    if super::sha(&request.sha)? != base_sha {
        return Err(super::fail(
            "Main request candidate SHA differs from base SHA",
        ));
    }

    let candidate = crate::ci_receipt::load(&results.join(super::CANDIDATE_RECEIPT))?;
    super::validate_receipt(&candidate, &base_sha)?;
    super::admit_evidence(results, &candidate)?;
    let gaps = super::receipt_gaps(&candidate);
    if !gaps.is_empty() {
        return Err(super::fail(format!(
            "incomplete main receipt cannot seed reusable base: {}",
            gaps.join("; ")
        )));
    }
    let paired_gaps = super::paired_base_gaps(&candidate, super::accept_exit(results)?);
    if !paired_gaps.is_empty() {
        return Err(super::fail(format!(
            "main run has paired base gaps: {}",
            paired_gaps.join("; ")
        )));
    }
    let diff = crate::signed_receipt::compare(&candidate, &candidate)?;
    if diff.blocks() {
        return Err(super::fail(
            "main receipt failed self-comparison; refusing reusable base publication",
        ));
    }

    let host_identity = candidate
        .host_identity
        .clone()
        .filter(SignedHostIdentity::is_complete)
        .ok_or_else(|| super::fail("main receipt lacks complete host_identity"))?;
    let key = compute_base_reuse_key(root, &base_sha, host_identity, bundle_path)
        .map_err(|e| super::fail(format!("cannot compute base reuse key: {e}")))?;
    let key_sha256 = key.key_sha256()?;
    let artifact_name = key.artifact_name()?;

    if output.exists() {
        fs::remove_dir_all(output)
            .map_err(|e| super::fail(format!("{}: {e}", output.display())))?;
    }
    let staged_base = output.join(super::BASE_DIR);
    fs::create_dir_all(&staged_base)
        .map_err(|e| super::fail(format!("{}: {e}", staged_base.display())))?;

    let entries =
        fs::read_dir(results).map_err(|e| super::fail(format!("{}: {e}", results.display())))?;
    for entry in entries {
        let entry = entry.map_err(|e| super::fail(format!("{}: {e}", results.display())))?;
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else {
            return Err(super::fail("non-UTF-8 entry in results directory"));
        };
        if matches!(
            name_str,
            "diff.json"
                | "comment.md"
                | "execution-error.txt"
                | "base-seal.json"
                | "base"
                | "posts.jsonl"
                | "publish-request.json"
        ) {
            continue;
        }
        let src_path = entry.path();
        let target_name = if name_str == super::CANDIDATE_RECEIPT {
            super::BASE_RECEIPT
        } else {
            name_str
        };
        let dst_path = staged_base.join(target_name);
        let kind = fs::symlink_metadata(&src_path)
            .map_err(|e| super::fail(format!("{}: {e}", src_path.display())))?
            .file_type();
        if kind.is_dir() {
            copy_regular_tree(&src_path, &dst_path)?;
        } else if kind.is_file() {
            let bytes = fs::read(&src_path)
                .map_err(|e| super::fail(format!("{}: {e}", src_path.display())))?;
            super::write_fresh(&dst_path, bytes)?;
        } else {
            return Err(super::fail(format!(
                "{} is not a regular file",
                src_path.display()
            )));
        }
    }

    let files = super::evidence_inventory(&staged_base)?;
    let seal = super::BaseSeal {
        base: base_sha.clone(),
        files,
        reuse: Some(ReuseSealMetadata {
            key: key.clone(),
            key_sha256,
            source_run_id: run_id,
            artifact_id: None,
        }),
    };
    let seal_bytes = serde_json::to_vec_pretty(&seal).map_err(|e| super::fail(e.to_string()))?;
    super::write_fresh(&output.join(super::BASE_SEAL), seal_bytes)?;

    verify_reusable_package(output, &base_sha, &key, Some(run_id), false)
        .map_err(|e| super::fail(format!("staged reusable base failed self-check: {e}")))?;

    if let Ok(gh_out) = std::env::var("GITHUB_OUTPUT") {
        use std::io::Write;
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&gh_out)
            .map_err(|e| super::fail(format!("{gh_out}: {e}")))?;
        writeln!(file, "artifact_name={artifact_name}")
            .map_err(|e| super::fail(format!("{gh_out}: {e}")))?;
    }
    Ok(artifact_name)
}

/// Re-verify `BaseSeal.reuse` on the hosted `publish` runner so a tampered or
/// stale seal in `signed-result` is refused closed.
pub(crate) fn verify_published_reuse_seal(
    reuse: &ReuseSealMetadata,
    expected_base: &str,
    base_receipt: &AcceptReceipt,
) -> Result<(u64, u64), ReceiptError> {
    let artifact_id = reuse
        .artifact_id
        .filter(|id| *id > 0)
        .ok_or_else(|| super::fail("base evidence seal: reused base lacks artifact_id"))?;
    if reuse.source_run_id == 0 {
        return Err(super::fail(
            "base evidence seal: reused base lacks source_run_id",
        ));
    }
    if reuse.key.schema_version != BASE_REUSE_SCHEMA_VERSION {
        return Err(super::fail(format!(
            "base evidence seal: unsupported reuse schema_version {}",
            reuse.key.schema_version
        )));
    }
    if reuse.key.base_sha != expected_base {
        return Err(super::fail(format!(
            "base evidence seal: reuse key names base {}, request names {expected_base}",
            reuse.key.base_sha
        )));
    }
    let computed_sha256 = reuse
        .key
        .key_sha256()
        .map_err(|e| super::fail(format!("base evidence seal: {e}")))?;
    if reuse.key_sha256 != computed_sha256 {
        return Err(super::fail(
            "base evidence seal: reuse key_sha256 does not match canonical key JSON",
        ));
    }
    verify_receipt_matches_key(base_receipt, &reuse.key)
        .map_err(|e| super::fail(format!("base evidence seal: {e}")))?;
    Ok((artifact_id, reuse.source_run_id))
}
