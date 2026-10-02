use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;

use crate::command::{CommandError, CommandOutput};

#[derive(Parser, Debug, Clone)]
pub struct ProvisionArgs {
    #[command(subcommand)]
    pub action: ProvisionAction,
}

#[derive(Subcommand, Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProvisionAction {
    #[command(about = "Provision static Linux and embed fixtures")]
    Fixtures,
    #[command(about = "Provision strict ARM64 closure probes")]
    Probes,
    #[command(about = "Provision both fixtures and probes before guest execution")]
    All,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvisioningReceipt {
    pub schema: String,
    pub schema_version: u32,
    pub source_head: String,
    pub dirty_inputs: bool,
    pub rustc_identity: RustcIdentity,
    pub targets: Vec<String>,
    pub libc: Vec<String>,
    pub build_scripts: Vec<FileDigest>,
    pub sources: Vec<FileDigest>,
    pub manifests: Vec<FileDigest>,
    pub lockfiles: Vec<FileDigest>,
    pub commands: Vec<ExecutedCommandReceipt>,
    pub executables: Vec<FileDigest>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RustcIdentity {
    pub release: String,
    pub commit_hash: String,
    pub host: String,
    pub raw: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileDigest {
    pub path: String,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutedCommandReceipt {
    pub program: String,
    pub argv: Vec<String>,
    pub exit_status: i32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixtureDeclaration {
    pub source: String,
    pub name: String,
    pub is_pie: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElfSummary {
    pub is_64bit: bool,
    pub is_little_endian: bool,
    pub machine: u16,
    pub is_arm64: bool,
    pub has_interpreter: bool,
    pub interpreter: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct ProbeEntry {
    class: String,
    #[allow(dead_code)]
    runner: String,
    excluded: bool,
}

pub trait CommandRunner: Send + Sync {
    fn run_checked(
        &self,
        program: &OsStr,
        argv: &[&OsStr],
        cwd: Option<&Path>,
    ) -> Result<CommandOutput, CommandError>;
}

pub struct DefaultCommandRunner;

impl CommandRunner for DefaultCommandRunner {
    fn run_checked(
        &self,
        program: &OsStr,
        argv: &[&OsStr],
        cwd: Option<&Path>,
    ) -> Result<CommandOutput, CommandError> {
        crate::command::run_checked(program, argv, cwd)
    }
}

#[derive(Debug, Error)]
pub enum FixtureValidationError {
    #[error("missing fixture at '{0}'")]
    Missing(PathBuf),

    #[error(
        "fixture at '{path}' has wrong architecture (expected ARM AArch64 0x00B7, found {found:#06x})"
    )]
    WrongArchitecture { path: PathBuf, found: u16 },

    #[error("fixture at '{path}' is dynamic or has dynamic interpreter: {interpreter:?}")]
    DynamicInterpreter {
        path: PathBuf,
        interpreter: Option<String>,
    },

    #[error("fixture at '{0}' is not executable")]
    NotExecutable(PathBuf),

    #[error("invalid ELF at '{path}': {details}")]
    InvalidElf { path: PathBuf, details: String },
}

#[derive(Debug, Error)]
pub enum ProbeValidationError {
    #[error("missing probe inventory at '{0}'")]
    MissingInventory(PathBuf),

    #[error("missing probe binary '{name}' for target '{target}' at '{path}'")]
    MissingBinary {
        name: String,
        target: String,
        path: PathBuf,
    },

    #[error("missing required helper probeinit for target '{target}' at '{path}'")]
    MissingProbeinit { target: String, path: PathBuf },

    #[error("probe binary at '{path}' has wrong architecture: {found:#06x}")]
    WrongArchitecture { path: PathBuf, found: u16 },

    #[error("probe binary at '{0}' is not executable")]
    NotExecutable(PathBuf),

    #[error("invalid ELF at '{path}': {details}")]
    InvalidElf { path: PathBuf, details: String },

    #[error("inventory error: {0}")]
    Inventory(String),
}

#[derive(Debug, Error)]
pub enum ProvisionError {
    #[error("prerequisite failure: {0}")]
    Prerequisite(String),

    #[error("command error: {0}")]
    Command(#[from] CommandError),

    #[error("I/O error at '{path}': {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("fixture validation error: {0}")]
    FixtureValidation(#[from] FixtureValidationError),

    #[error("probe validation error: {0}")]
    ProbeValidation(#[from] ProbeValidationError),

    #[error("receipt error: {0}")]
    Receipt(String),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

pub fn parse_fixture_declarations(script_content: &str) -> Vec<FixtureDeclaration> {
    let mut decls = Vec::new();
    for line in script_content.lines() {
        let trimmed = line.trim();
        let (is_pie, rest) = if let Some(r) = trimmed.strip_prefix("build_fixture ") {
            (false, r)
        } else if let Some(r) = trimmed.strip_prefix("build_pie_fixture ") {
            (true, r)
        } else {
            continue;
        };

        let parts: Vec<&str> = rest.split('"').filter(|s| !s.trim().is_empty()).collect();
        if parts.len() >= 2 {
            decls.push(FixtureDeclaration {
                source: parts[0].to_string(),
                name: parts[1].to_string(),
                is_pie,
            });
        }
    }
    decls
}

pub fn inspect_elf(data: &[u8]) -> Result<ElfSummary, String> {
    if data.len() < 64 {
        return Err("data too short for ELF64 header".to_string());
    }
    if &data[0..4] != b"\x7fELF" {
        return Err("not an ELF file (invalid magic)".to_string());
    }
    let is_64bit = data[4] == 2;
    let is_little_endian = data[5] == 1;
    if !is_64bit || !is_little_endian {
        return Ok(ElfSummary {
            is_64bit,
            is_little_endian,
            machine: 0,
            is_arm64: false,
            has_interpreter: false,
            interpreter: None,
        });
    }

    let machine = u16::from_le_bytes([data[18], data[19]]);
    let is_arm64 = machine == 0x00B7;

    let phoff = u64::from_le_bytes(
        data[32..40]
            .try_into()
            .map_err(|_| "failed to read phoff")?,
    ) as usize;
    let phentsize = u16::from_le_bytes(
        data[54..56]
            .try_into()
            .map_err(|_| "failed to read phentsize")?,
    ) as usize;
    let phnum = u16::from_le_bytes(
        data[56..58]
            .try_into()
            .map_err(|_| "failed to read phnum")?,
    ) as usize;

    let mut has_interpreter = false;
    let mut interpreter = None;

    if phentsize >= 8 && phoff > 0 {
        for i in 0..phnum {
            let offset = phoff + i * phentsize;
            if offset + phentsize > data.len() {
                break;
            }
            let p_type = u32::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]);
            if p_type == 3 {
                has_interpreter = true;
                if phentsize >= 40 {
                    let p_offset = u64::from_le_bytes(
                        data[offset + 8..offset + 16]
                            .try_into()
                            .map_err(|_| "read p_offset")?,
                    ) as usize;
                    let p_filesz = u64::from_le_bytes(
                        data[offset + 32..offset + 40]
                            .try_into()
                            .map_err(|_| "read p_filesz")?,
                    ) as usize;
                    if p_offset + p_filesz <= data.len() && p_filesz > 0 {
                        let mut raw_str = &data[p_offset..p_offset + p_filesz];
                        if raw_str.ends_with(b"\0") {
                            raw_str = &raw_str[..raw_str.len() - 1];
                        }
                        interpreter = Some(String::from_utf8_lossy(raw_str).into_owned());
                    }
                }
            }
        }
    }

    Ok(ElfSummary {
        is_64bit,
        is_little_endian,
        machine,
        is_arm64,
        has_interpreter,
        interpreter,
    })
}

fn is_executable(path: &Path) -> Result<bool, std::io::Error> {
    let metadata = fs::metadata(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        Ok(metadata.permissions().mode() & 0o111 != 0)
    }
    #[cfg(not(unix))]
    {
        Ok(true)
    }
}

pub fn compute_sha256(path: &Path) -> Result<String, std::io::Error> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = std::io::Read::read(&mut file, &mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn validate_single_fixture(path: &Path, root: &Path) -> Result<(), FixtureValidationError> {
    let rel = path.strip_prefix(root).unwrap_or(path).to_path_buf();
    if !path.is_file() {
        return Err(FixtureValidationError::Missing(rel));
    }

    let exec =
        is_executable(path).map_err(|_| FixtureValidationError::NotExecutable(rel.clone()))?;
    if !exec {
        return Err(FixtureValidationError::NotExecutable(rel));
    }

    let data = fs::read(path).map_err(|e| FixtureValidationError::InvalidElf {
        path: rel.clone(),
        details: e.to_string(),
    })?;

    let elf = inspect_elf(&data).map_err(|e| FixtureValidationError::InvalidElf {
        path: rel.clone(),
        details: e,
    })?;

    if !elf.is_64bit || !elf.is_arm64 {
        return Err(FixtureValidationError::WrongArchitecture {
            path: rel,
            found: elf.machine,
        });
    }

    if elf.has_interpreter {
        return Err(FixtureValidationError::DynamicInterpreter {
            path: rel,
            interpreter: elf.interpreter,
        });
    }

    Ok(())
}

pub fn validate_fixtures(
    root: &Path,
    declarations: &[FixtureDeclaration],
) -> Result<Vec<PathBuf>, FixtureValidationError> {
    let mut validated = Vec::new();
    let fixtures_dir =
        root.join("fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release");

    for decl in declarations {
        let path = fixtures_dir.join(&decl.name);
        validate_single_fixture(&path, root)?;
        validated.push(path);
    }

    let embed_dir = root.join("target/embed-fixtures");
    for name in [
        "interceptor-probe-aarch64",
        "zone-readers-aarch64",
        "el1-sched-aarch64",
    ] {
        let path = embed_dir.join(name);
        validate_single_fixture(&path, root)?;
        validated.push(path);
    }

    Ok(validated)
}

pub fn validate_probes(
    root: &Path,
    inventory_path: &Path,
) -> Result<Vec<PathBuf>, ProbeValidationError> {
    let rel_inv = inventory_path
        .strip_prefix(root)
        .unwrap_or(inventory_path)
        .to_path_buf();
    if !inventory_path.is_file() {
        return Err(ProbeValidationError::MissingInventory(rel_inv));
    }

    let content = fs::read_to_string(inventory_path).map_err(|e| {
        ProbeValidationError::Inventory(format!(
            "cannot read inventory {}: {e}",
            inventory_path.display()
        ))
    })?;

    let inventory: HashMap<String, ProbeEntry> = serde_json::from_str(&content).map_err(|e| {
        ProbeValidationError::Inventory(format!(
            "cannot parse inventory {}: {e}",
            inventory_path.display()
        ))
    })?;

    let mut selected_names: Vec<String> = inventory
        .into_iter()
        .filter(|(_, entry)| {
            (entry.class == "conformance" || entry.class == "helper") && !entry.excluded
        })
        .map(|(name, _)| name)
        .collect();
    selected_names.sort();

    let targets = [
        ("aarch64-unknown-linux-musl", false),
        ("aarch64-unknown-linux-gnu", true),
    ];

    let mut validated = Vec::new();

    for (target_triple, allow_dynamic) in targets {
        let target_dir = root
            .join("conformance-probes/target")
            .join(target_triple)
            .join("release");
        for name in &selected_names {
            let path = target_dir.join(name);
            let rel = path.strip_prefix(root).unwrap_or(&path).to_path_buf();
            if !path.is_file() {
                if name == "probeinit" {
                    return Err(ProbeValidationError::MissingProbeinit {
                        target: target_triple.to_string(),
                        path: rel,
                    });
                } else {
                    return Err(ProbeValidationError::MissingBinary {
                        name: name.clone(),
                        target: target_triple.to_string(),
                        path: rel,
                    });
                }
            }

            let exec = is_executable(&path)
                .map_err(|_| ProbeValidationError::NotExecutable(rel.clone()))?;
            if !exec {
                return Err(ProbeValidationError::NotExecutable(rel));
            }

            let data = fs::read(&path).map_err(|e| ProbeValidationError::InvalidElf {
                path: rel.clone(),
                details: e.to_string(),
            })?;

            let elf = inspect_elf(&data).map_err(|e| ProbeValidationError::InvalidElf {
                path: rel.clone(),
                details: e,
            })?;

            if !elf.is_64bit || !elf.is_arm64 {
                return Err(ProbeValidationError::WrongArchitecture {
                    path: rel,
                    found: elf.machine,
                });
            }

            if !allow_dynamic && elf.has_interpreter {
                return Err(ProbeValidationError::InvalidElf {
                    path: rel,
                    details: "musl probe binary has dynamic interpreter".to_string(),
                });
            }

            validated.push(path);
        }
    }

    Ok(validated)
}

fn check_prerequisites(
    root: &Path,
    action: ProvisionAction,
    runner: &dyn CommandRunner,
) -> Result<(), ProvisionError> {
    // Check rustc
    let rustc_out = runner
        .run_checked(OsStr::new("rustc"), &[OsStr::new("-vV")], Some(root))
        .map_err(|_| {
            ProvisionError::Prerequisite(
                "rustc is not available or failed to report identity".into(),
            )
        })?;

    // Check rustup target aarch64-unknown-linux-musl
    let rustup_out = runner
        .run_checked(
            OsStr::new("rustup"),
            &[
                OsStr::new("target"),
                OsStr::new("list"),
                OsStr::new("--installed"),
            ],
            Some(root),
        )
        .map_err(|_| {
            ProvisionError::Prerequisite(
                "rustup is not available to inspect installed targets".into(),
            )
        })?;

    let installed_targets = &rustup_out.stdout;
    if !installed_targets
        .lines()
        .any(|l| l.trim() == "aarch64-unknown-linux-musl")
    {
        return Err(ProvisionError::Prerequisite(
            "missing required Rust target: aarch64-unknown-linux-musl; install it with: rustup target add aarch64-unknown-linux-musl".into(),
        ));
    }

    // Check rust-lld if sysroot exists
    let host_line = rustc_out
        .stdout
        .lines()
        .find(|l| l.starts_with("host:"))
        .map(|l| l.trim_start_matches("host:").trim());
    if let Some(host) = host_line
        && let Ok(sysroot_out) = runner.run_checked(
            OsStr::new("rustc"),
            &[OsStr::new("--print"), OsStr::new("sysroot")],
            Some(root),
        )
    {
        let sysroot = sysroot_out.stdout.trim();
        let sysroot_path = Path::new(sysroot);
        if sysroot_path.is_dir() {
            let lld = sysroot_path
                .join("lib/rustlib")
                .join(host)
                .join("bin/rust-lld");
            if !lld.is_file() {
                return Err(ProvisionError::Prerequisite(format!(
                    "missing required rust-lld at {}; install with rustup component add llvm-tools-preview",
                    lld.display()
                )));
            }
        }
    }

    if matches!(action, ProvisionAction::Probes | ProvisionAction::All) {
        let arch = std::env::consts::ARCH;
        if arch != "aarch64" && arch != "arm64" {
            return Err(ProvisionError::Prerequisite(
                "--closure-arm64 requires an arm64 host".into(),
            ));
        }

        // Check docker
        runner
            .run_checked(OsStr::new("docker"), &[OsStr::new("info")], Some(root))
            .map_err(|_| {
                ProvisionError::Prerequisite(
                    "Docker daemon is not running or docker CLI is not installed; probe closure builds require a running native ARM64 Docker daemon".into(),
                )
            })?;
    }

    Ok(())
}

fn collect_rs_files(dir: &Path, base: &Path, list: &mut Vec<PathBuf>) {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                collect_rs_files(&path, base, list);
            } else if path.is_file()
                && path.extension().and_then(|s| s.to_str()) == Some("rs")
                && let Ok(rel) = path.strip_prefix(base)
            {
                list.push(rel.to_path_buf());
            }
        }
    }
}

pub fn generate_receipt(
    root: &Path,
    action: ProvisionAction,
    runner: &dyn CommandRunner,
    commands: Vec<ExecutedCommandReceipt>,
    validated_executables: &[PathBuf],
) -> Result<ProvisioningReceipt, ProvisionError> {
    // 1. source HEAD
    let head_out = runner
        .run_checked(
            OsStr::new("git"),
            &[OsStr::new("rev-parse"), OsStr::new("HEAD")],
            Some(root),
        )
        .map_err(|e| {
            ProvisionError::Receipt(format!(
                "git rev-parse HEAD failed to establish identity: {e}"
            ))
        })?;
    let source_head = head_out.stdout.trim().to_string();
    if source_head.is_empty() {
        return Err(ProvisionError::Receipt(
            "empty git rev-parse HEAD output".into(),
        ));
    }

    // 2. dirty inputs
    let status_out = runner
        .run_checked(
            OsStr::new("git"),
            &[OsStr::new("status"), OsStr::new("--porcelain")],
            Some(root),
        )
        .map_err(|e| ProvisionError::Receipt(format!("git status failed: {e}")))?;
    let dirty_inputs = !status_out.stdout.trim().is_empty();

    // 3. rustc identity
    let rustc_out = runner
        .run_checked(OsStr::new("rustc"), &[OsStr::new("-vV")], Some(root))
        .map_err(|e| ProvisionError::Receipt(format!("rustc -vV failed: {e}")))?;
    let raw = rustc_out.stdout;
    let mut release = String::new();
    let mut commit_hash = String::new();
    let mut host = String::new();
    for line in raw.lines() {
        if let Some(r) = line.strip_prefix("release:") {
            release = r.trim().to_string();
        } else if let Some(c) = line.strip_prefix("commit-hash:") {
            commit_hash = c.trim().to_string();
        } else if let Some(h) = line.strip_prefix("host:") {
            host = h.trim().to_string();
        }
    }
    let rustc_identity = RustcIdentity {
        release,
        commit_hash,
        host,
        raw,
    };

    // 4. Targets and libc
    let (targets, libc) = match action {
        ProvisionAction::Fixtures => (
            vec!["aarch64-unknown-linux-musl".to_string()],
            vec!["musl".to_string()],
        ),
        ProvisionAction::Probes | ProvisionAction::All => (
            vec![
                "aarch64-unknown-linux-musl".to_string(),
                "aarch64-unknown-linux-gnu".to_string(),
            ],
            vec!["musl".to_string(), "gnu".to_string()],
        ),
    };

    // 5. Build scripts digests
    let mut build_script_rel_paths = vec![
        "scripts/build-linux-fixtures.sh",
        "scripts/build-embed-interceptor-probe.sh",
        "scripts/build-embed-zone-readers.sh",
        "scripts/build-embed-el1-sched.sh",
    ];
    if matches!(action, ProvisionAction::Probes | ProvisionAction::All) {
        build_script_rel_paths.push("scripts/build-probes.sh");
        build_script_rel_paths.push("scripts/probe-inventory.py");
    }
    let mut build_scripts = Vec::new();
    for rel in build_script_rel_paths {
        let abs = root.join(rel);
        if abs.is_file() {
            let sha256 = compute_sha256(&abs).map_err(|e| ProvisionError::Io {
                path: abs.clone(),
                source: e,
            })?;
            build_scripts.push(FileDigest {
                path: rel.to_string(),
                sha256,
            });
        }
    }

    // 6. Manifests & Lockfiles
    let mut manifest_paths = vec![
        "fixtures/linux-aarch64-hello/Cargo.toml",
        "fixtures/embed-interceptor-probe/Cargo.toml",
        "fixtures/embed-zone-readers/Cargo.toml",
        "fixtures/embed-el1-sched/Cargo.toml",
    ];
    let mut lockfile_paths = vec![
        "fixtures/linux-aarch64-hello/Cargo.lock",
        "fixtures/embed-interceptor-probe/Cargo.lock",
        "fixtures/embed-zone-readers/Cargo.lock",
        "fixtures/embed-el1-sched/Cargo.lock",
    ];
    if matches!(action, ProvisionAction::Probes | ProvisionAction::All) {
        manifest_paths.push("conformance-probes/Cargo.toml");
        lockfile_paths.push("conformance-probes/Cargo.lock");
    }

    let mut manifests = Vec::new();
    for rel in manifest_paths {
        let abs = root.join(rel);
        if abs.is_file() {
            let sha256 = compute_sha256(&abs).map_err(|e| ProvisionError::Io {
                path: abs.clone(),
                source: e,
            })?;
            manifests.push(FileDigest {
                path: rel.to_string(),
                sha256,
            });
        }
    }

    let mut lockfiles = Vec::new();
    for rel in lockfile_paths {
        let abs = root.join(rel);
        if abs.is_file() {
            let sha256 = compute_sha256(&abs).map_err(|e| ProvisionError::Io {
                path: abs.clone(),
                source: e,
            })?;
            lockfiles.push(FileDigest {
                path: rel.to_string(),
                sha256,
            });
        }
    }

    // 7. Sources digests
    let mut source_rel_paths = Vec::new();
    collect_rs_files(
        &root.join("fixtures/linux-aarch64-hello/src"),
        root,
        &mut source_rel_paths,
    );
    collect_rs_files(
        &root.join("fixtures/embed-interceptor-probe/src"),
        root,
        &mut source_rel_paths,
    );
    collect_rs_files(
        &root.join("fixtures/embed-zone-readers/src"),
        root,
        &mut source_rel_paths,
    );
    collect_rs_files(
        &root.join("fixtures/embed-el1-sched/src"),
        root,
        &mut source_rel_paths,
    );
    if matches!(action, ProvisionAction::Probes | ProvisionAction::All) {
        collect_rs_files(
            &root.join("conformance-probes/src"),
            root,
            &mut source_rel_paths,
        );
        let inv_path = PathBuf::from("conformance-probes/probe-inventory.json");
        if root.join(&inv_path).is_file() {
            source_rel_paths.push(inv_path);
        }
    }
    source_rel_paths.sort();
    source_rel_paths.dedup();

    let mut sources = Vec::new();
    for rel in source_rel_paths {
        let abs = root.join(&rel);
        if abs.is_file() {
            let sha256 = compute_sha256(&abs).map_err(|e| ProvisionError::Io {
                path: abs.clone(),
                source: e,
            })?;
            sources.push(FileDigest {
                path: rel.to_string_lossy().to_string(),
                sha256,
            });
        }
    }

    // 8. Executables
    let mut executables = Vec::new();
    for abs in validated_executables {
        let rel = abs
            .strip_prefix(root)
            .unwrap_or(abs)
            .to_string_lossy()
            .to_string();
        let sha256 = compute_sha256(abs).map_err(|e| ProvisionError::Io {
            path: abs.clone(),
            source: e,
        })?;
        executables.push(FileDigest { path: rel, sha256 });
    }
    executables.sort_by(|a, b| a.path.cmp(&b.path));

    Ok(ProvisioningReceipt {
        schema: "carrick.provisioning.v1".to_string(),
        schema_version: 1,
        source_head,
        dirty_inputs,
        rustc_identity,
        targets,
        libc,
        build_scripts,
        sources,
        manifests,
        lockfiles,
        commands,
        executables,
    })
}

pub fn publish_receipt_atomic(
    root: &Path,
    receipt: &ProvisioningReceipt,
) -> Result<PathBuf, ProvisionError> {
    let results_dir = root.join("target/test-results");
    fs::create_dir_all(&results_dir).map_err(|e| ProvisionError::Io {
        path: results_dir.clone(),
        source: e,
    })?;

    let target_file = results_dir.join("provisioning.json");
    let tmp_file = results_dir.join(format!(".provisioning.json.{}.tmp", std::process::id()));

    let content = serde_json::to_string_pretty(receipt)?;
    fs::write(&tmp_file, content.as_bytes()).map_err(|e| ProvisionError::Io {
        path: tmp_file.clone(),
        source: e,
    })?;

    fs::rename(&tmp_file, &target_file).map_err(|e| ProvisionError::Io {
        path: target_file.clone(),
        source: e,
    })?;

    Ok(target_file)
}

pub fn run(
    root: Option<&Path>,
    action: ProvisionAction,
    writer: &mut dyn std::io::Write,
) -> Result<(), ProvisionError> {
    let runner = DefaultCommandRunner;
    run_with_runner(root, action, &runner, writer)
}

pub fn run_with_runner(
    root: Option<&Path>,
    action: ProvisionAction,
    runner: &dyn CommandRunner,
    writer: &mut dyn std::io::Write,
) -> Result<(), ProvisionError> {
    let current_dir;
    let root_path = match root {
        Some(r) => r.to_path_buf(),
        None => {
            current_dir = std::env::current_dir().map_err(|e| ProvisionError::Io {
                path: PathBuf::from("."),
                source: e,
            })?;
            current_dir
        }
    };

    let canonical_root = fs::canonicalize(&root_path).unwrap_or(root_path);

    // 1. Check prerequisites
    check_prerequisites(&canonical_root, action, runner)?;

    let mut executed_commands = Vec::new();

    // 2. Run builders
    if matches!(action, ProvisionAction::Fixtures | ProvisionAction::All) {
        for script in [
            "scripts/build-linux-fixtures.sh",
            "scripts/build-embed-interceptor-probe.sh",
            "scripts/build-embed-zone-readers.sh",
            "scripts/build-embed-el1-sched.sh",
        ] {
            writeln!(writer, "xtask provision: running {script}...").map_err(|e| {
                ProvisionError::Io {
                    path: PathBuf::from("writer"),
                    source: e,
                }
            })?;
            let output = runner.run_checked(OsStr::new(script), &[], Some(&canonical_root))?;
            executed_commands.push(ExecutedCommandReceipt {
                program: script.to_string(),
                argv: Vec::new(),
                exit_status: output.status.code().unwrap_or(0),
            });
        }
    }

    if matches!(action, ProvisionAction::Probes | ProvisionAction::All) {
        let script = "scripts/build-probes.sh";
        let argv = [OsStr::new("--closure-arm64")];
        writeln!(
            writer,
            "xtask provision: running {script} --closure-arm64..."
        )
        .map_err(|e| ProvisionError::Io {
            path: PathBuf::from("writer"),
            source: e,
        })?;
        let output = runner.run_checked(OsStr::new(script), &argv, Some(&canonical_root))?;
        executed_commands.push(ExecutedCommandReceipt {
            program: script.to_string(),
            argv: vec!["--closure-arm64".to_string()],
            exit_status: output.status.code().unwrap_or(0),
        });
    }

    // 3. Validate
    let mut validated_executables = Vec::new();
    if matches!(action, ProvisionAction::Fixtures | ProvisionAction::All) {
        let script_path = canonical_root.join("scripts/build-linux-fixtures.sh");
        let script_content = fs::read_to_string(&script_path).map_err(|e| ProvisionError::Io {
            path: script_path,
            source: e,
        })?;
        let declarations = parse_fixture_declarations(&script_content);
        let mut fixtures = validate_fixtures(&canonical_root, &declarations)?;
        validated_executables.append(&mut fixtures);
    }

    if matches!(action, ProvisionAction::Probes | ProvisionAction::All) {
        let inventory_path = canonical_root.join("conformance-probes/probe-inventory.json");
        let mut probes = validate_probes(&canonical_root, &inventory_path)?;
        validated_executables.append(&mut probes);
    }

    // 4. Generate & publish receipt atomically
    let receipt = generate_receipt(
        &canonical_root,
        action,
        runner,
        executed_commands,
        &validated_executables,
    )?;

    let published_path = publish_receipt_atomic(&canonical_root, &receipt)?;
    writeln!(
        writer,
        "xtask provision: published receipt at {}",
        published_path.display()
    )
    .map_err(|e| ProvisionError::Io {
        path: PathBuf::from("writer"),
        source: e,
    })?;

    Ok(())
}
