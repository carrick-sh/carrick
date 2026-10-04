//! Immutable, exact-commit guest artifacts. No guest execution or Docker.
use clap::Subcommand;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use thiserror::Error;

use crate::{command, probe_inventory, provision};

const SCHEMA: &str = "carrick.fixtures.v1";
pub const INSTALLED_MANIFEST: &str = "target/fixtures/installed.json";
const INPUTS: &[&str] = &[
    // The EL1 scheduler fixture depends on workspace path crates. Hash the
    // tracked workspace conservatively, including root dependency/patch and
    // lint declarations, so adding a transitive local crate cannot escape
    // provenance without needing Cargo or a registry on the restore host.
    "Cargo.toml",
    "Cargo.lock",
    "crates",
    "conformance-probes",
    "fixtures/linux-aarch64-hello",
    "fixtures/embed-interceptor-probe",
    "fixtures/embed-zone-readers",
    "fixtures/embed-icache-reuse",
    "fixtures/embed-el1-sched",
    "scripts/build-linux-fixtures.sh",
    "scripts/build-embed-interceptor-probe.sh",
    "scripts/build-embed-zone-readers.sh",
    "scripts/build-embed-icache-reuse.sh",
    "scripts/build-embed-el1-sched.sh",
    "rust-toolchain.toml",
    ".cargo/config.toml",
];
const EMBED: &[(&str, &str)] = &[
    ("embed-interceptor-probe", "interceptor-probe"),
    ("embed-zone-readers", "zone-readers"),
    ("embed-icache-reuse", "icache-reuse"),
    ("embed-el1-sched", "el1-sched"),
];

#[derive(clap::Args, Debug)]
pub struct FixturesArgs {
    #[command(subcommand)]
    pub action: FixturesAction,
}

#[derive(Subcommand, Debug)]
pub enum FixturesAction {
    /// Build in a fresh exact-SHA snapshot on Linux (native ARM or cross).
    Build {
        #[arg(long)]
        sha: String,
        #[arg(long, help = "Bundle store (default: target/fixtures/bundles)")]
        output: Option<PathBuf>,
    },
    /// Validate the entire bundle before installing any executable.
    Restore {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long, help = "Expected commit (default: checkout HEAD)")]
        sha: Option<String>,
    },
    /// Check a bundle or, by default, every installed signed-tier fixture.
    Verify {
        #[arg(long)]
        manifest: Option<PathBuf>,
        #[arg(long, help = "Expected commit (default: checkout HEAD)")]
        sha: Option<String>,
    },
}

#[derive(Debug, Error)]
pub enum FixturesError {
    #[error("fixture validation failed: {0}")]
    Invalid(String),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Command(#[from] command::CommandError),
    #[error(transparent)]
    Inventory(#[from] probe_inventory::InventoryError),
}

type Result<T> = std::result::Result<T, FixturesError>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct CommitSha(String);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ContentHash(String);

fn hex_identity(value: &str, len: usize) -> Result<()> {
    if value.len() != len
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(FixturesError::Invalid(format!(
            "invalid {len}-digit identity: {value}"
        )));
    }
    Ok(())
}

impl TryFrom<String> for CommitSha {
    type Error = FixturesError;
    fn try_from(value: String) -> Result<Self> {
        hex_identity(&value, 40)?;
        Ok(Self(value))
    }
}
impl From<CommitSha> for String {
    fn from(value: CommitSha) -> Self {
        value.0
    }
}
impl TryFrom<String> for ContentHash {
    type Error = FixturesError;
    fn try_from(value: String) -> Result<Self> {
        hex_identity(&value, 64)?;
        Ok(Self(value))
    }
}
impl From<ContentHash> for String {
    fn from(value: ContentHash) -> Self {
        value.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GuestTarget {
    #[serde(rename = "aarch64-unknown-linux-musl")]
    Musl,
    #[serde(rename = "aarch64-unknown-linux-gnu")]
    Gnu,
}
impl GuestTarget {
    fn triple(self) -> &'static str {
        match self {
            Self::Musl => "aarch64-unknown-linux-musl",
            Self::Gnu => "aarch64-unknown-linux-gnu",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Executable {
    pub path: String,
    pub target: GuestTarget,
    pub sha256: ContentHash,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Toolchain {
    pub rustc: String,
    pub cargo: String,
    pub gnu_linker: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub schema: String,
    pub source_head: CommitSha,
    pub sources: BTreeMap<String, ContentHash>,
    pub toolchain: Toolchain,
    pub executables: Vec<Executable>,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Installed {
    manifest_sha256: ContentHash,
    manifest: Manifest,
}

fn hash_bytes(bytes: &[u8]) -> ContentHash {
    ContentHash(format!("{:x}", Sha256::digest(bytes)))
}
fn hash_file(path: &Path) -> Result<ContentHash> {
    Ok(ContentHash(provision::compute_sha256(path)?))
}
fn fail(message: impl Into<String>) -> FixturesError {
    FixturesError::Invalid(message.into())
}

fn safe_path(root: &Path, relative: &str) -> Result<PathBuf> {
    let mut path = root.to_path_buf();
    for component in Path::new(relative).components() {
        let Component::Normal(name) = component else {
            return Err(fail(format!("unsafe fixture path: {relative}")));
        };
        path.push(name);
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(fail(format!("symlink fixture path: {}", path.display())));
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    if path == root {
        return Err(fail("empty fixture path"));
    }
    Ok(path)
}

fn git(root: &Path, args: &[&str]) -> Result<String> {
    Ok(command::run_checked("git", args, Some(root))?.stdout)
}
fn expected_head(root: &Path, sha: Option<&str>) -> Result<CommitSha> {
    let head = CommitSha::try_from(git(root, &["rev-parse", "HEAD"])?.trim().to_owned())?;
    if let Some(sha) = sha {
        let requested = CommitSha::try_from(sha.to_owned())?;
        if requested != head {
            return Err(fail(format!(
                "wrong SHA: expected {}, checkout is {}",
                requested.0, head.0
            )));
        }
    }
    Ok(head)
}
fn source_hashes(root: &Path) -> Result<BTreeMap<String, ContentHash>> {
    let mut args = vec!["status", "--porcelain", "--untracked-files=all", "--"];
    args.extend(INPUTS);
    if !git(root, &args)?.trim().is_empty() {
        return Err(fail("dirty fixture source inputs"));
    }
    let mut args = vec!["ls-files", "-z", "--"];
    args.extend(INPUTS);
    let paths = git(root, &args)?;
    let mut sources = BTreeMap::new();
    for relative in paths.split('\0').filter(|p| !p.is_empty()) {
        sources.insert(relative.to_owned(), hash_file(&safe_path(root, relative)?)?);
    }
    if sources.is_empty() {
        return Err(fail("empty fixture source inventory"));
    }
    Ok(sources)
}

fn probe_names(root: &Path) -> Result<Vec<String>> {
    let inventory =
        probe_inventory::load_inventory(&root.join("conformance-probes/probe-inventory.json"))?;
    probe_inventory::validate_source_membership(
        &inventory.keys().cloned().collect(),
        &probe_inventory::read_probe_source_names(&root.join("conformance-probes/src/bin"))?,
    )?;
    let names: Vec<_> = inventory
        .into_iter()
        .filter(|(_, row)| !row.excluded && matches!(row.class.as_str(), "conformance" | "helper"))
        .map(|(name, _)| name)
        .collect();
    if !names.iter().any(|n| n == "probeinit") {
        return Err(fail("probeinit missing from fixture inventory"));
    }
    for name in &names {
        if name.is_empty()
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            return Err(fail(format!("invalid probe name: {name}")));
        }
    }
    Ok(names)
}

pub fn executable_inventory(root: &Path) -> Result<BTreeMap<String, GuestTarget>> {
    let mut paths = BTreeMap::new();
    let names = probe_names(root)?;
    for target in [GuestTarget::Musl, GuestTarget::Gnu] {
        for name in &names {
            paths.insert(
                format!(
                    "conformance-probes/target/{}/release/{name}",
                    target.triple()
                ),
                target,
            );
        }
    }
    let script = fs::read_to_string(root.join("scripts/build-linux-fixtures.sh"))?;
    let declarations = provision::parse_fixture_declarations(&script);
    if declarations.is_empty() {
        return Err(fail("empty Linux fixture declarations"));
    }
    for declaration in declarations {
        let relative = format!(
            "fixtures/linux-aarch64-hello/target/{}/release/{}",
            GuestTarget::Musl.triple(),
            declaration.name
        );
        safe_path(root, &relative)?;
        if paths.insert(relative, GuestTarget::Musl).is_some() {
            return Err(fail("duplicate Linux fixture"));
        }
    }
    for (_, name) in EMBED {
        paths.insert(
            format!("target/embed-fixtures/{name}-aarch64"),
            GuestTarget::Musl,
        );
    }
    Ok(paths)
}

fn validate_executable(path: &Path, executable: &Executable) -> Result<()> {
    if hash_file(path)? != executable.sha256 {
        return Err(fail(format!(
            "executable hash mismatch: {}",
            executable.path
        )));
    }
    let metadata = fs::metadata(path)?;
    if !metadata.is_file() {
        return Err(fail(format!(
            "not a regular executable: {}",
            path.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o111 == 0 {
            return Err(fail(format!("not executable: {}", path.display())));
        }
    }
    let elf = provision::inspect_elf(&fs::read(path)?).map_err(fail)?;
    if !elf.is_64bit || !elf.is_little_endian || !elf.is_arm64 {
        return Err(fail(format!("not an ARM64 ELF: {}", executable.path)));
    }
    match executable.target {
        GuestTarget::Musl if elf.has_interpreter => {
            return Err(fail(format!(
                "musl fixture has an interpreter: {}",
                executable.path
            )));
        }
        GuestTarget::Gnu if elf.interpreter.as_deref() != Some("/lib/ld-linux-aarch64.so.1") => {
            return Err(fail(format!(
                "GNU fixture lacks the ARM64 glibc interpreter: {}",
                executable.path
            )));
        }
        _ => {}
    }
    Ok(())
}

fn validate_manifest(root: &Path, manifest: &Manifest, expected: &CommitSha) -> Result<()> {
    if manifest.schema != SCHEMA {
        return Err(fail("unknown fixture manifest schema"));
    }
    if &manifest.source_head != expected {
        return Err(fail(format!(
            "wrong SHA: manifest {}, expected {}",
            manifest.source_head.0, expected.0
        )));
    }
    if manifest.sources != source_hashes(root)? {
        return Err(fail("fixture source hashes or inventory mismatch"));
    }
    let pin = fs::read_to_string(root.join("rust-toolchain.toml"))?;
    let release = manifest
        .toolchain
        .rustc
        .lines()
        .find_map(|l| l.strip_prefix("release: "))
        .ok_or_else(|| fail("missing rustc release identity"))?;
    if !pin
        .lines()
        .any(|l| l.trim() == format!("channel = \"{release}\""))
        || manifest.toolchain.cargo.trim().is_empty()
        || manifest.toolchain.gnu_linker.trim().is_empty()
    {
        return Err(fail("missing or mismatched fixture toolchain identity"));
    }
    let expected_paths = executable_inventory(root)?;
    let actual: BTreeMap<_, _> = manifest
        .executables
        .iter()
        .map(|e| (e.path.clone(), e.target))
        .collect();
    if actual.len() != manifest.executables.len() || actual != expected_paths {
        return Err(fail(
            "incomplete, duplicate, or unexpected fixture executable inventory",
        ));
    }
    Ok(())
}

fn manifest_bytes(manifest: &Manifest) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec_pretty(manifest)?)
}

pub fn verify_bundle(root: &Path, path: &Path, sha: Option<&str>) -> Result<Manifest> {
    let expected = expected_head(root, sha)?;
    let bytes = fs::read(path)?;
    let parent = path
        .parent()
        .ok_or_else(|| fail("manifest has no bundle directory"))?;
    if parent.file_name().and_then(|n| n.to_str()) != Some(&hash_bytes(&bytes).0) {
        return Err(fail("manifest content address mismatch"));
    }
    let manifest: Manifest = serde_json::from_slice(&bytes)?;
    if manifest_bytes(&manifest)? != bytes {
        return Err(fail("noncanonical fixture manifest"));
    }
    validate_manifest(root, &manifest, &expected)?;
    for executable in &manifest.executables {
        validate_executable(
            &safe_path(parent, &format!("objects/{}", executable.sha256.0))?,
            executable,
        )?;
    }
    Ok(manifest)
}

pub fn verify_installed(root: &Path) -> Result<Manifest> {
    let expected = expected_head(root, None)?;
    let installed: Installed =
        serde_json::from_slice(&fs::read(safe_path(root, INSTALLED_MANIFEST)?)?)?;
    if hash_bytes(&manifest_bytes(&installed.manifest)?) != installed.manifest_sha256 {
        return Err(fail("installed manifest hash mismatch"));
    }
    validate_manifest(root, &installed.manifest, &expected)?;
    for executable in &installed.manifest.executables {
        validate_executable(&safe_path(root, &executable.path)?, executable)?;
    }
    Ok(installed.manifest)
}

fn publish_file(path: &Path, bytes: &[u8], executable: bool) -> Result<()> {
    let parent = path.parent().ok_or_else(|| fail("output has no parent"))?;
    fs::create_dir_all(parent)?;
    let mut temp = tempfile::NamedTempFile::new_in(parent)?;
    temp.write_all(bytes)?;
    #[cfg(unix)]
    if executable {
        use std::os::unix::fs::PermissionsExt;
        temp.as_file()
            .set_permissions(fs::Permissions::from_mode(0o755))?;
    }
    #[cfg(not(unix))]
    let _ = executable;
    temp.as_file().sync_all()?;
    temp.persist(path).map_err(|e| e.error)?;
    Ok(())
}

pub fn restore(root: &Path, path: &Path, sha: Option<&str>) -> Result<()> {
    let manifest = verify_bundle(root, path, sha)?;
    let parent = path
        .parent()
        .ok_or_else(|| fail("manifest has no parent"))?;
    let stage = tempfile::tempdir()?;
    // Capture and revalidate before changing destinations; a changed bundle
    // cannot confer acceptance via a previously verified path.
    for (index, executable) in manifest.executables.iter().enumerate() {
        let from = safe_path(parent, &format!("objects/{}", executable.sha256.0))?;
        let to = stage.path().join(index.to_string());
        fs::copy(from, &to)?;
        validate_executable(&to, executable)?;
        safe_path(root, &executable.path)?;
    }
    let installed_path = safe_path(root, INSTALLED_MANIFEST)?;
    match fs::remove_file(&installed_path) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    for (index, executable) in manifest.executables.iter().enumerate() {
        publish_file(
            &safe_path(root, &executable.path)?,
            &fs::read(stage.path().join(index.to_string()))?,
            true,
        )?;
    }
    let installed = Installed {
        manifest_sha256: hash_bytes(&manifest_bytes(&manifest)?),
        manifest,
    };
    publish_file(
        &installed_path,
        &serde_json::to_vec_pretty(&installed)?,
        false,
    )?;
    verify_installed(root)?;
    Ok(())
}

fn run_build(command: &mut Command) -> Result<()> {
    // Never capture a many-bin build into memory; errors retain their full log.
    let status = command.status()?;
    if !status.success() {
        return Err(fail(format!(
            "fixture build command failed: {command:?} ({status})"
        )));
    }
    Ok(())
}

pub fn build(root: &Path, sha: &str, output: Option<&Path>) -> Result<PathBuf> {
    if std::env::consts::OS != "linux" {
        return Err(fail("fixtures build requires Linux; restore on cloudmac"));
    }
    let expected = expected_head(root, Some(sha))?;
    source_hashes(root)?;
    let snapshot = tempfile::tempdir()?;
    let archive = snapshot.path().join("source.tar");
    run_build(
        Command::new("git")
            .current_dir(root)
            .args(["archive", "--format=tar", "--output"])
            .arg(&archive)
            .arg(&expected.0),
    )?;
    let source = snapshot.path().join("source");
    fs::create_dir(&source)?;
    run_build(
        Command::new("tar")
            .args(["-xf"])
            .arg(&archive)
            .arg("-C")
            .arg(&source),
    )?;
    // Git metadata is deliberately separate; source_hashes is captured from
    // the original clean checkout again after builds to reject source races.
    let rustc = command::run_checked("rustc", ["-vV"], Some(root))?.stdout;
    let cargo = command::run_checked("cargo", ["--version"], Some(root))?.stdout;
    let host = rustc
        .lines()
        .find_map(|l| l.strip_prefix("host: "))
        .ok_or_else(|| fail("missing compiler host"))?;
    let sysroot = command::run_checked("rustc", ["--print", "sysroot"], Some(root))?.stdout;
    let lld = Path::new(sysroot.trim())
        .join("lib/rustlib")
        .join(host)
        .join("bin/rust-lld");
    let linker = if std::env::consts::ARCH == "aarch64" {
        "cc"
    } else {
        "aarch64-linux-gnu-gcc"
    };
    let gnu_linker = command::run_checked(linker, ["--version"], Some(root))?.stdout;
    let toolchain = Toolchain {
        rustc,
        cargo,
        gnu_linker,
    };
    let names = probe_names(&source)?;
    for target in [GuestTarget::Musl, GuestTarget::Gnu] {
        let mut command = Command::new("cargo");
        command
            .current_dir(source.join("conformance-probes"))
            .args([
                "build",
                "--locked",
                "--release",
                "--target",
                target.triple(),
            ])
            .env_remove("CARGO_TARGET_DIR")
            .env_remove("RUSTFLAGS")
            .env_remove("CARGO_ENCODED_RUSTFLAGS");
        match target {
            GuestTarget::Musl => {
                command.env("CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER", &lld);
            }
            GuestTarget::Gnu => {
                command.env("CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER", linker);
            }
        }
        for name in &names {
            command.args(["--bin", name]);
        }
        run_build(&mut command)?;
    }
    for script in [
        "scripts/build-linux-fixtures.sh",
        "scripts/build-embed-interceptor-probe.sh",
        "scripts/build-embed-zone-readers.sh",
        "scripts/build-embed-icache-reuse.sh",
        "scripts/build-embed-el1-sched.sh",
    ] {
        run_build(
            Command::new("bash")
                .current_dir(&source)
                .arg(script)
                .env_remove("CARGO_TARGET_DIR")
                .env_remove("RUSTFLAGS")
                .env_remove("CARGO_ENCODED_RUSTFLAGS")
                .env("CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER", &lld),
        )?;
    }
    if expected_head(root, Some(sha))? != expected {
        return Err(fail("checkout changed during fixture build"));
    }
    let sources = source_hashes(root)?;
    // Match the build snapshot byte-for-byte with the recorded source inputs.
    for (path, hash) in &sources {
        if &hash_file(&safe_path(&source, path)?)? != hash {
            return Err(fail(format!("build snapshot source mismatch: {path}")));
        }
    }
    let mut executables = Vec::new();
    for (path, target) in executable_inventory(&source)? {
        let executable = Executable {
            sha256: hash_file(&source.join(&path))?,
            path,
            target,
        };
        validate_executable(&source.join(&executable.path), &executable)?;
        executables.push(executable);
    }
    let manifest = Manifest {
        schema: SCHEMA.into(),
        source_head: expected.clone(),
        sources,
        toolchain,
        executables,
    };
    validate_manifest(root, &manifest, &expected)?;
    let bytes = manifest_bytes(&manifest)?;
    let store = output
        .map(Path::to_path_buf)
        .unwrap_or_else(|| root.join("target/fixtures/bundles"));
    let sha_dir = store.join(&expected.0);
    fs::create_dir_all(&sha_dir)?;
    let stage = tempfile::tempdir_in(&sha_dir)?;
    fs::create_dir(stage.path().join("objects"))?;
    for executable in &manifest.executables {
        let to = stage.path().join("objects").join(&executable.sha256.0);
        if !to.exists() {
            fs::copy(source.join(&executable.path), to)?;
        }
    }
    fs::write(stage.path().join("manifest.json"), &bytes)?;
    let bundle = sha_dir.join(&hash_bytes(&bytes).0);
    if bundle.exists() {
        verify_bundle(root, &bundle.join("manifest.json"), Some(sha))?;
    } else {
        fs::rename(stage.path(), &bundle)?;
    }
    let path = bundle.join("manifest.json");
    verify_bundle(root, &path, Some(sha))?;
    Ok(path)
}

pub fn run(root: &Path, action: FixturesAction, writer: &mut dyn Write) -> Result<()> {
    match action {
        FixturesAction::Build { sha, output } => {
            let path = build(root, &sha, output.as_deref())?;
            writeln!(writer, "fixtures: bundle manifest {}", path.display())?;
        }
        FixturesAction::Restore { manifest, sha } => {
            restore(root, &manifest, sha.as_deref())?;
            writeln!(
                writer,
                "fixtures: restored and verified all signed-tier executables"
            )?;
        }
        FixturesAction::Verify { manifest, sha } => {
            expected_head(root, sha.as_deref())?;
            let manifest = match manifest {
                Some(path) => verify_bundle(root, &path, sha.as_deref())?,
                None => verify_installed(root)?,
            };
            writeln!(
                writer,
                "fixtures: verified {} executables for {}",
                manifest.executables.len(),
                manifest.source_head.0
            )?;
        }
    }
    Ok(())
}
