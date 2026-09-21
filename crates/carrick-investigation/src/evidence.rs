//! Local execution receipts. These detect stale or mismatched evidence; they are
//! not a security boundary against a user deliberately forging local files.
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::InvestigationError;
use carrick_conformance_contract::{
    ContractFailure, ContractId, ContractObservation, ContractRegistry, ExecutionLayer, evaluate,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

fn invalid(message: impl ToString) -> InvestigationError {
    InvestigationError::InvalidEvidence(message.to_string())
}

pub fn hash_file(path: &Path) -> Result<String, InvestigationError> {
    Ok(format!("{:x}", Sha256::digest(std::fs::read(path)?)))
}

fn git(root: &Path, args: &[&str]) -> Result<Vec<u8>, InvestigationError> {
    let out = Command::new("git")
        .args(["-c", "core.fsmonitor=false"])
        .args(args)
        .current_dir(root)
        .output()?;
    if !out.status.success() {
        return Err(invalid(String::from_utf8_lossy(&out.stderr)));
    }
    Ok(out.stdout)
}

/// Includes dirty tracked and untracked build inputs, not just HEAD. Excludes
/// documentation and runtime outputs so writing a report does not stale a run.
pub fn source_identity(root: &Path) -> Result<String, InvestigationError> {
    let names = git(
        root,
        &[
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            "-z",
            "--",
            "crates",
            "conformance-contracts",
            "scripts",
            "fixtures",
            "conformance-probes",
            "Cargo.toml",
            "Cargo.lock",
            "rust-toolchain.toml",
            ".cargo",
        ],
    )?;
    let mut names: Vec<_> = names.split(|b| *b == 0).filter(|n| !n.is_empty()).collect();
    names.sort();
    names.dedup();
    let mut hash = Sha256::new();
    for name in names {
        let name_str = std::str::from_utf8(name).map_err(invalid)?;
        hash.update(name);
        hash.update([0]);
        let input = root.join(name_str);
        if std::fs::symlink_metadata(&input).is_ok_and(|m| m.file_type().is_symlink()) {
            hash.update(std::fs::read_link(&input)?.as_os_str().as_encoded_bytes());
            continue;
        }
        match std::fs::read(input) {
            Ok(bytes) => {
                hash.update((bytes.len() as u64).to_le_bytes());
                hash.update(bytes);
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => hash.update(b"deleted"),
            Err(e) => return Err(e.into()),
        }
    }
    Ok(format!("{:x}", hash.finalize()))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionReceipt {
    pub schema: u32,
    pub root: PathBuf,
    pub revision: String,
    pub source_sha256: String,
    pub program: PathBuf,
    pub program_sha256: String,
    pub arguments: Vec<String>,
    pub stdout: PathBuf,
    pub stdout_sha256: String,
    pub stderr: PathBuf,
    pub stderr_sha256: String,
    pub contract: ContractId,
    pub layer: ExecutionLayer,
}

/// Execute a bounded, VM-free observation producer. It must emit a JSON array
/// of ContractObservation, including an independently checked fixture.active
/// assertion. Guest producers require a separate signed runner and are refused.
pub fn capture_vm_free(
    root: &Path,
    program: &Path,
    args: &[String],
    directory: &Path,
    contract: ContractId,
    timeout: Duration,
) -> Result<PathBuf, InvestigationError> {
    if timeout.is_zero() {
        return Err(invalid("positive execution budget required"));
    }
    let root = root.canonicalize()?;
    let program = program.canonicalize()?;
    std::fs::create_dir(directory)?;
    let directory = directory.canonicalize()?;
    let source_sha256 = source_identity(&root)?;
    let program_sha256 = hash_file(&program)?;
    let revision = String::from_utf8(git(&root, &["rev-parse", "HEAD"])?)
        .map_err(invalid)?
        .trim()
        .to_string();
    let stdout = directory.join("stdout.json");
    let stderr = directory.join("stderr.log");
    let mut child = Command::new(&program)
        .args(args)
        .current_dir(&root)
        .env_remove("CARRICK_CONTRACT_FAULT")
        .env("CARRICK_OBSERVATION_SOURCE", &source_sha256)
        .stdin(Stdio::null())
        .stdout(std::fs::File::create(&stdout)?)
        .stderr(std::fs::File::create(&stderr)?)
        .spawn()?;
    let start = Instant::now();
    let poll_interval = Duration::from_millis(100);
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if start.elapsed() >= timeout {
            child.kill()?;
            child.wait()?;
            return Err(invalid(
                "observation producer exceeded budget; no receipt issued",
            ));
        }
        std::thread::sleep(poll_interval);
    };
    if !status.success() {
        return Err(invalid("observation producer failed; see captured streams"));
    }
    if source_identity(&root)? != source_sha256 || hash_file(&program)? != program_sha256 {
        return Err(invalid("source or executable changed during experiment"));
    }
    let receipt = ExecutionReceipt {
        schema: 1,
        root,
        revision,
        source_sha256,
        program,
        program_sha256,
        arguments: args.to_vec(),
        stdout_sha256: hash_file(&stdout)?,
        stdout,
        stderr_sha256: hash_file(&stderr)?,
        stderr,
        contract,
        layer: ExecutionLayer::VmFree,
    };
    let path = directory.join("receipt.json");
    std::fs::write(&path, serde_json::to_vec_pretty(&receipt)?)?;
    Ok(path)
}

pub fn validate_red(path: &Path) -> Result<ExecutionReceipt, InvestigationError> {
    let receipt: ExecutionReceipt = serde_json::from_slice(&std::fs::read(path)?)?;
    if receipt.schema != 1 || receipt.layer != ExecutionLayer::VmFree {
        return Err(invalid("unsupported receipt schema or execution layer"));
    }
    if receipt.revision.len() != 40
        || !receipt.revision.bytes().all(|b| b.is_ascii_hexdigit())
        || source_identity(&receipt.root)? != receipt.source_sha256
        || hash_file(&receipt.program)? != receipt.program_sha256
        || hash_file(&receipt.stdout)? != receipt.stdout_sha256
        || hash_file(&receipt.stderr)? != receipt.stderr_sha256
    {
        return Err(invalid("stale or mismatched execution receipt"));
    }
    let observations: Vec<ContractObservation> =
        serde_json::from_slice(&std::fs::read(&receipt.stdout)?)?;
    let registry = ContractRegistry::load(&receipt.root).map_err(invalid)?;
    let contract = registry
        .get(&receipt.contract)
        .ok_or_else(|| invalid("unregistered evidence contract"))?;
    if observations.is_empty() {
        return Err(invalid("no executed observations"));
    }
    // Validate all rows before evaluation: an early red row must not mask a
    // later incomplete measurement or a fixture which never became active.
    for observation in &observations {
        observation.validate().map_err(invalid)?;
        let work = observation
            .work
            .as_ref()
            .ok_or_else(|| invalid("VM-free evidence requires a work snapshot"))?;
        for budget in &contract.structural_budgets {
            let metric = match budget.budget {
                carrick_conformance_contract::Budget::Exact { metric, .. }
                | carrick_conformance_contract::Budget::UpperBound { metric, .. }
                | carrick_conformance_contract::Budget::Affine { metric, .. } => metric,
            };
            if work.get(metric).is_none() {
                return Err(invalid("required work metric missing"));
            }
        }
        match evaluate(contract, std::slice::from_ref(observation)) {
            Ok(_)
            | Err(
                ContractFailure::SemanticMismatch { .. }
                | ContractFailure::WorkBudgetExceeded { .. }
                | ContractFailure::ScalingViolation { .. },
            ) => {}
            Err(other) => return Err(invalid(other)),
        }

        if observation.contract_id != receipt.contract
            || observation.layer != receipt.layer
            || observation.fixture_identity != contract.fixture
            || observation.implementation_revision != receipt.source_sha256
            || !contract.scale_points.contains(&observation.scale)
            || !observation
                .semantic_assertions
                .iter()
                .any(|a| a.name == "fixture.active" && a.passed)
        {
            return Err(invalid(
                "observation identity, scale or fixture activity mismatch",
            ));
        }
    }
    match evaluate(contract, &observations) {
        Err(
            ContractFailure::SemanticMismatch { .. }
            | ContractFailure::WorkBudgetExceeded { .. }
            | ContractFailure::ScalingViolation { .. },
        ) => Ok(receipt),
        Err(other) => Err(invalid(other)),
        Ok(_) => Err(invalid("contract passed: receipt is not red evidence")),
    }
}
